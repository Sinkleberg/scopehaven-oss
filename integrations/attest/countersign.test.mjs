// ScopeHaven countersignature (scopehaven-countersign/1): the hash-only request, the countersigning step, the RFC 3161
// timestamp and both verifiers. Every key here is made in memory for the run (test-tsa.mjs makes the TSA's); the interim
// ScopeHaven key that signed the sample pack is not in the repository, and only its public half is in the key set.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { digest } from '../../src/domain.mjs';
import { generateSigningKey, signFiles } from './sign.mjs';
import { pae, verifyEnvelope } from './verify.mjs';
import { COUNTERSIGN_MEANING, KEYSET_URL, combined, readKeyset, verifyCountersignature, verifyTimestamp } from './verify-countersign.mjs';
import { REQUEST_FIELDS, countersignRequest, countersignService, requestTimestamp } from './countersign.mjs';
import { KEYSET_FILE, PUBLIC_KEY_FILE, countersignNames, main } from './cli.mjs';
import { createTestTsa } from './test-tsa.mjs';

const VERIFIER = fileURLToPath(new URL('./verify_envelope.py', import.meta.url));
const SITE_KEYSET = fileURLToPath(new URL('../../../site/.well-known/scopehaven-keys.json', import.meta.url));
const SAMPLE = fileURLToPath(new URL('../../examples/sample-evidence-pack/pack/', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven-countersign-')); await chmod(dir, 0o700); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
const python = args => new Promise(resolve => execFile('python3', ['-I', VERIFIER, ...args], { maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => resolve({ code: error ? error.code : 0, output: JSON.parse(stdout) })));

// A real run export of the owned synthetic fixture, signed by an operator key: the evidence a pack holds.
const work = await mkdtemp(join(tmpdir(), 'scopehaven-countersign-run-'));
process.on('exit', () => rm(work, { recursive: true, force: true }));
const run = await runAssessment('demo-vulnerable'), store = createStore(join(work, 'data'));
await store.save(run);
await mkdir(join(work, 'out'), { mode: 0o700 });
await exportRun({ runId: run.id, format: 'json', outputFile: join(work, 'out', 'run.json'), dataDir: join(work, 'data') });
const RUN = await readFile(join(work, 'out', 'run.json'));
const OPERATOR = generateSigningKey(), SCOPEHAVEN = generateSigningKey(), FORGER = generateSigningKey();
const { envelope: ENVELOPE } = signFiles([{ name: 'run.json', content: RUN }], { privateKey: OPERATOR.privatePem, version: '0.7.0' });
const tsa = createTestTsa(), otherTsa = createTestTsa({ name: 'other-tsa.local' });

const keysetFor = ({ keys = [{ key: SCOPEHAVEN }], authorities = [tsa.authority('http://127.0.0.1/tsr')] } = {}) => `${JSON.stringify({
  schema: 'scopehaven-keys/1', publisher: 'ScopeHaven', url: KEYSET_URL, updated: '2026-10-29T00:00:00.000Z',
  countersigningKeys: keys.map(({ key, status = 'active', notBefore = '2026-01-01T00:00:00.000Z', notAfter = null, revokedAt = null }) => ({ keyid: key.keyid, publicKey: key.publicPem, status, notBefore, notAfter, revokedAt, note: 'test key' })),
  timestampAuthorities: authorities, policy: { rotation: 'test', revocation: 'test' } }, null, 2)}\n`;
const KEYSET = keysetFor();
const stampWith = (authority, options) => async hex => authority.stamp(Buffer.from(hex, 'hex'), options);
const countersign = (envelope = ENVELOPE, { key = SCOPEHAVEN, authority = tsa, licenceId = 'test-licence', now, stamp } = {}) =>
  countersignService(JSON.stringify(countersignRequest(envelope, { licenceId, release: '0.7.0' })), { privateKey: key.privatePem, now, timestamp: stamp ?? stampWith(authority) });
const GOOD = await countersign();

// Both verifiers on one case: the operator key, the files, then the countersignature against a key set.
// A countersignature or timestamp given as null is absent.
async function bothVerify(t, { envelope = ENVELOPE, files = { 'run.json': RUN }, publicPem = OPERATOR.publicPem, countersignature = GOOD.envelope, timestamp = GOOD.timestamp, keyset = KEYSET }) {
  countersignature ??= undefined; timestamp ??= undefined;
  const first = verifyEnvelope({ envelope, publicKey: publicPem, files: new Map(Object.entries(files)) });
  const node = combined(first, first.verified ? verifyCountersignature({ envelope, countersignature, timestamp, keyset }) : null);
  const dir = await scratch(t);
  for (const [name, content] of Object.entries(files)) await writeFile(join(dir, name), content);
  await writeFile(join(dir, 'operator.pub.pem'), publicPem); await writeFile(join(dir, 'evidence.dsse.json'), envelope); await writeFile(join(dir, 'keys.json'), keyset);
  if (countersignature !== undefined) await writeFile(join(dir, 'evidence.countersign.dsse.json'), countersignature);
  if (timestamp !== undefined) await writeFile(join(dir, 'evidence.countersign.tsr'), timestamp);
  const args = ['--key', join(dir, 'operator.pub.pem'), '--envelope', join(dir, 'evidence.dsse.json'), '--dir', dir, '--scopehaven-keys', join(dir, 'keys.json'),
    '--countersignature', join(dir, 'evidence.countersign.dsse.json'), '--timestamp', join(dir, 'evidence.countersign.tsr')];
  const [py, cli] = await Promise.all([python(args), main(['verify', ...args])]);
  assert.equal(cli.output.verdict, node.verdict, 'the Node CLI and library agree');
  assert.equal(py.output.verdict, node.verdict, `Python agrees with Node (${py.output.reason} vs ${node.reason})`);
  assert.equal(py.output.reason, node.reason, 'Python gives the same reason as Node');
  assert.equal(py.code, cli.code);
  return { node, py: py.output, code: py.code };
}

test('the countersign request carries hashes, the licence, the release and a nonce, and nothing from the files', () => {
  const request = countersignRequest(ENVELOPE, { licenceId: 'lic_123', release: '0.7.0' });
  assert.deepEqual(Object.keys(request), REQUEST_FIELDS);
  const body = JSON.stringify(request), env = JSON.parse(ENVELOPE);
  assert.equal(request.statementSha256, sha256(Buffer.from(env.payload, 'base64')));
  assert.equal(request.signerKeyid, OPERATOR.keyid);
  assert.equal(request.signatureSha256, sha256(Buffer.from(env.signatures[0].sig, 'base64')));
  for (const leak of [run.id, run.targetId, run.applicationId, run.suiteHash, sha256(RUN), 'run.json']) assert.ok(!body.includes(leak), `the request does not carry ${leak}`);
  // The service takes exactly those fields: one more is refused, so no content can ride along.
  return assert.rejects(countersignService(JSON.stringify({ ...request, files: 'x' }), { privateKey: SCOPEHAVEN.privatePem, timestamp: stampWith(tsa) }), /exactly the fields/);
});

test('a countersigned envelope verifies in both verifiers, with the TSA time and the bound operator key', async t => {
  const { node, py, code } = await bothVerify(t, {});
  assert.equal(code, 0);
  assert.equal(node.verdict, 'verified');
  assert.equal(node.countersignature.keyid, SCOPEHAVEN.keyid);
  assert.equal(node.countersignature.firstSignerKeyid, OPERATOR.keyid);
  assert.equal(node.countersignature.meaning, COUNTERSIGN_MEANING);
  assert.match(node.countersignature.timestamp.genTime, /^2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/);
  assert.deepEqual(py.countersignature.timestamp, node.countersignature.timestamp);
  assert.deepEqual(py.countersignature.selfChecks, node.countersignature.selfChecks);
  assert.ok(node.countersignature.selfChecks.length >= 9 && node.countersignature.selfChecks.every(c => c.observed === 'rejected'));
});

test('a forged pack re-signed with another key fails against the published key set', async t => {
  // The rehearsal's forgery: the finding erased, the run's unkeyed integrity hash recomputed, the files re-signed with a new key.
  const forged = JSON.parse(RUN.toString('utf8'));
  forged.results = forged.results.map(r => ({ ...r, status: 'pass' }));
  const { integrity, notes, ...core } = forged;
  forged.integrity = { ...integrity, sha256: digest(core) };
  const forgedRun = Buffer.from(JSON.stringify(forged, null, 2));
  const { envelope: forgedEnvelope } = signFiles([{ name: 'run.json', content: forgedRun }], { privateKey: FORGER.privatePem, version: '0.7.0' });
  const base = { envelope: forgedEnvelope, files: { 'run.json': forgedRun }, publicPem: FORGER.publicPem };
  // Alone, the first signature still verifies under the forger's key, as the rehearsal showed.
  assert.equal(verifyEnvelope({ envelope: forgedEnvelope, publicKey: FORGER.publicPem, files: new Map([['run.json', forgedRun]]) }).verdict, 'verified');
  // Kept genuine countersignature: it names another statement.
  assert.equal((await bothVerify(t, base)).node.reason, 'countersign-subject-mismatch');
  // The forger's own countersignature, even with a genuine-looking timestamp: its key is not published.
  const own = await countersign(forgedEnvelope, { key: FORGER });
  const { node, code } = await bothVerify(t, { ...base, countersignature: own.envelope, timestamp: own.timestamp });
  assert.equal(node.reason, 'countersign-key-unknown');
  assert.equal(code, 1);
  // No countersignature at all, when the reviewer asks for one.
  const missing = await bothVerify(t, { ...base, countersignature: null, timestamp: null });
  assert.equal(missing.node.reason, 'countersign-missing');
  assert.equal(missing.code, 1);
  // The genuine statement re-signed by the forger, with the genuine countersignature: it names the operator's key and signature.
  const env = JSON.parse(ENVELOPE);
  const sig = sign(null, pae(env.payloadType, Buffer.from(env.payload, 'base64')), createPrivateKey(FORGER.privatePem)).toString('base64');
  const resigned = JSON.stringify({ ...env, signatures: [{ keyid: FORGER.keyid, sig }] });
  assert.equal((await bothVerify(t, { envelope: resigned, publicPem: FORGER.publicPem })).node.reason, 'countersign-signer-mismatch');
});

test('timestamps: another digest, an untrusted TSA, a tampered token and a certificate not limited to time stamping are rejected', async t => {
  const otherDigest = { ...GOOD, timestamp: tsa.stamp(Buffer.alloc(32, 7)) };
  assert.equal((await bothVerify(t, { countersignature: otherDigest.envelope, timestamp: otherDigest.timestamp })).node.reason, 'timestamp-imprint-mismatch');
  const untrusted = await countersign(ENVELOPE, { authority: otherTsa });
  assert.equal((await bothVerify(t, { countersignature: untrusted.envelope, timestamp: untrusted.timestamp })).node.reason, 'timestamp-untrusted');
  const tampered = Buffer.from(GOOD.timestamp); tampered[tampered.length - 5] ^= 1;
  assert.equal((await bothVerify(t, { timestamp: tampered })).node.reason, 'timestamp-invalid');
  for (const leafExtendedKeyUsage of ['not-critical', 'none']) {
    const loose = createTestTsa({ leafExtendedKeyUsage }), signed = await countersign(ENVELOPE, { authority: loose });
    const { node } = await bothVerify(t, { countersignature: signed.envelope, timestamp: signed.timestamp, keyset: keysetFor({ authorities: [loose.authority('http://127.0.0.1/tsr')] }) });
    assert.equal(node.reason, 'timestamp-invalid');
    assert.match(node.detail, /time stamping only/);
  }
  const expired = createTestTsa({ leafValidDays: 1 }), late = await countersign(ENVELOPE, { authority: expired, stamp: stampWith(expired, { genTime: new Date(Date.now() + 3 * 86400000) }) });
  const { node } = await bothVerify(t, { countersignature: late.envelope, timestamp: late.timestamp, keyset: keysetFor({ authorities: [expired.authority('http://127.0.0.1/tsr')] }) });
  assert.match(node.detail, /not valid at the stamped time/);
});

test('rotation and revocation follow the TSA time, not either signer\'s clock', async t => {
  const genTime = (await bothVerify(t, {})).node.countersignature.timestamp.genTime, later = new Date(Date.parse(genTime) + 1000).toISOString();
  // Revoked after the stamp: still valid. Revoked at or before it: rejected.
  assert.equal((await bothVerify(t, { keyset: keysetFor({ keys: [{ key: SCOPEHAVEN, status: 'revoked', revokedAt: later }] }) })).node.verdict, 'verified');
  assert.equal((await bothVerify(t, { keyset: keysetFor({ keys: [{ key: SCOPEHAVEN, status: 'revoked', revokedAt: genTime }] }) })).node.reason, 'countersign-key-revoked');
  // Retired after the stamp: valid. A key whose window starts after the stamp: rejected.
  assert.equal((await bothVerify(t, { keyset: keysetFor({ keys: [{ key: SCOPEHAVEN, status: 'retired', notAfter: later }] }) })).node.verdict, 'verified');
  assert.equal((await bothVerify(t, { keyset: keysetFor({ keys: [{ key: SCOPEHAVEN, notBefore: later }] }) })).node.reason, 'countersign-key-not-valid');
  // A countersigner clock far ahead of the TSA's is refused.
  const ahead = await countersign(ENVELOPE, { now: new Date(Date.now() + 3600000) });
  assert.equal((await bothVerify(t, { countersignature: ahead.envelope, timestamp: ahead.timestamp })).node.reason, 'countersign-time-inconsistent');
  // A key set whose key id is not its key's, or whose TSA root is not the certificate named, is refused outright.
  const wrongId = JSON.parse(KEYSET); wrongId.countersigningKeys[0].keyid = OPERATOR.keyid;
  assert.equal((await bothVerify(t, { keyset: JSON.stringify(wrongId) })).node.reason, 'keyset-invalid');
  const wrongRoot = JSON.parse(KEYSET); wrongRoot.timestampAuthorities[0].rootCertificate = otherTsa.authority('x').rootCertificate;
  assert.equal((await bothVerify(t, { keyset: JSON.stringify(wrongRoot) })).node.reason, 'keyset-invalid');
});

test('a verifier that accepts every signature fails its own countersignature controls', async () => {
  const accepting = verifyCountersignature({ envelope: ENVELOPE, countersignature: GOOD.envelope, timestamp: GOOD.timestamp, keyset: KEYSET }, { checkSignature: () => true });
  assert.equal(accepting.verdict, 'self-check-failed');
  assert.match(accepting.detail, /countersign-payload-tampered/);
});

test('Python copies with the imprint or revocation check removed fail their own controls', async t => {
  const dir = await scratch(t), source = await readFile(VERIFIER, 'utf8');
  const mutations = {
    imprint: ['_octets(imprint[1]).hex() != digest', 'False'],
    revocation: ['if entry["revokedAt"] is not None and gen_time >= entry["revokedAt"]:', 'if False:'],
  };
  await writeFile(join(dir, 'run.json'), RUN); await writeFile(join(dir, 'operator.pub.pem'), OPERATOR.publicPem); await writeFile(join(dir, 'evidence.dsse.json'), ENVELOPE);
  await writeFile(join(dir, 'keys.json'), KEYSET); await writeFile(join(dir, 'cs.json'), GOOD.envelope); await writeFile(join(dir, 'cs.tsr'), GOOD.timestamp);
  for (const [name, [from, to]] of Object.entries(mutations)) {
    assert.equal(source.split(from).length, 2, `${name}: the mutated line is unique`);
    const copy = join(dir, `mutant_${name}.py`);
    await writeFile(copy, source.replace(from, to));
    const result = await new Promise(resolve => execFile('python3', ['-I', copy, '--key', join(dir, 'operator.pub.pem'), '--envelope', join(dir, 'evidence.dsse.json'), '--dir', dir,
      '--scopehaven-keys', join(dir, 'keys.json'), '--countersignature', join(dir, 'cs.json'), '--timestamp', join(dir, 'cs.tsr')], (error, stdout) => resolve({ code: error ? error.code : 0, output: JSON.parse(stdout) })));
    assert.equal(result.code, 3, `${name}: exit 3`);
    assert.equal(result.output.verdict, 'self-check-failed', name);
  }
});

test('the CLI countersigns over loopback HTTP with a TSA from the key set, writes two new files and never overwrites', async t => {
  const { server, url } = await tsa.listen();
  t.after(() => server.close());
  const dir = await scratch(t), keyDir = join(dir, 'keys');
  await mkdir(keyDir, { mode: 0o700 });
  await writeFile(join(keyDir, 'scopehaven.pem'), SCOPEHAVEN.privatePem, { mode: 0o600 });
  await writeFile(join(dir, 'run.json'), RUN); await writeFile(join(dir, 'evidence.dsse.json'), ENVELOPE); await writeFile(join(dir, PUBLIC_KEY_FILE), OPERATOR.publicPem);
  await writeFile(join(dir, 'keys.json'), keysetFor({ authorities: [tsa.authority(url)] }));
  const args = ['countersign', '--envelope', join(dir, 'evidence.dsse.json'), '--key', join(keyDir, 'scopehaven.pem'), '--licence-id', 'lic_test', '--scopehaven-keys', join(dir, 'keys.json'), '--tsa-url', url];
  const made = await main(args);
  assert.equal(made.code, 0, JSON.stringify(made.output));
  assert.deepEqual(Object.keys(made.output.sent), REQUEST_FIELDS);
  const names = countersignNames(join(dir, 'evidence.dsse.json'));
  assert.equal(made.output.countersignature, names.countersignature);
  const verified = await main(['verify', '--key', join(dir, PUBLIC_KEY_FILE), '--envelope', join(dir, 'evidence.dsse.json'), '--dir', dir, '--scopehaven-keys', join(dir, 'keys.json'),
    '--countersignature', names.countersignature, '--timestamp', names.timestamp]);
  assert.equal(verified.code, 0);
  assert.equal(verified.output.countersignature.firstSignerKeyid, OPERATOR.keyid);
  const again = await main(args);
  assert.equal(again.code, 2);
  assert.match(again.output.error, /EEXIST|exists/);
  // A TSA the key set does not name is refused before anything is sent.
  const other = await main([...args.slice(0, -1), 'http://127.0.0.1:9/tsr']);
  assert.equal(other.code, 2);
  // Half the countersignature flags is a usage error in both CLIs.
  const half = ['--key', join(dir, PUBLIC_KEY_FILE), '--envelope', join(dir, 'evidence.dsse.json'), '--dir', dir, '--scopehaven-keys', join(dir, 'keys.json')];
  assert.equal((await main(['verify', ...half])).code, 2);
  assert.equal((await python(half)).code, 2);
});

test('the timestamp client refuses a redirect, so the digest reaches only the TSA it was given', async t => {
  let reached = 0;
  const other = createServer((req, res) => { reached++; req.resume(); res.writeHead(500); res.end(); });
  await new Promise(resolve => other.listen(0, '127.0.0.1', resolve));
  const redirecting = createServer((req, res) => { req.resume(); res.writeHead(307, { location: `http://127.0.0.1:${other.address().port}/tsr` }); res.end(); });
  await new Promise(resolve => redirecting.listen(0, '127.0.0.1', resolve));
  t.after(() => { other.close(); redirecting.close(); });
  const { authorities } = readKeyset(KEYSET);
  await assert.rejects(requestTimestamp('a'.repeat(64), { url: `http://127.0.0.1:${redirecting.address().port}/tsr`, authorities }));
  assert.equal(reached, 0);
});

test('the published key set is well formed, and the site serves the same bytes', { skip: existsSync(SITE_KEYSET) ? false : 'the scopehaven.dev site is not part of this repository' }, async () => {
  const [repo, site] = await Promise.all([readFile(KEYSET_FILE), readFile(SITE_KEYSET)]);
  assert.ok(repo.equals(site), 'site/.well-known/scopehaven-keys.json is a byte copy of integrations/attest/scopehaven-keys.json');
  const { keys, authorities } = readKeyset(repo);
  assert.ok(keys.size >= 1 && authorities.length >= 1);
  for (const entry of keys.values()) assert.ok(['active', 'interim'].includes(entry.status) || entry.notAfter !== null || entry.revokedAt !== null);
  assert.deepEqual(authorities.map(a => a.name), ['freetsa.org']);
  const set = JSON.parse(repo.toString('utf8'));
  assert.doesNotMatch(repo.toString('utf8'), /PRIVATE KEY/);
  assert.equal(set.url, KEYSET_URL);
});

test('the sample evidence pack on main verifies offline with both verifiers against the published key set', async () => {
  const files = await readdir(SAMPLE);
  for (const name of ['evidence-pack.dsse.json', 'evidence-pack.countersign.dsse.json', 'evidence-pack.countersign.tsr', PUBLIC_KEY_FILE]) assert.ok(files.includes(name), name);
  const args = ['--key', join(SAMPLE, PUBLIC_KEY_FILE), '--envelope', join(SAMPLE, 'evidence-pack.dsse.json'), '--dir', SAMPLE, '--scopehaven-keys', KEYSET_FILE,
    '--countersignature', join(SAMPLE, 'evidence-pack.countersign.dsse.json'), '--timestamp', join(SAMPLE, 'evidence-pack.countersign.tsr')];
  const [py, node] = await Promise.all([python(args), main(['verify', ...args])]);
  assert.equal(node.code, 0, JSON.stringify(node.output.detail));
  assert.equal(py.code, 0, JSON.stringify(py.output.detail));
  assert.equal(node.output.countersignature.timestamp.tsa, 'freetsa.org');
  assert.deepEqual(py.output.countersignature.timestamp, node.output.countersignature.timestamp);
  assert.equal(node.output.countersignature.keyid, JSON.parse(await readFile(KEYSET_FILE, 'utf8')).countersigningKeys[0].keyid);
  // Every per-file envelope in the pack verifies too (without the countersignature, which covers the folder envelope).
  for (const name of files.filter(f => f.endsWith('.dsse.json') && !f.includes('countersign') && f !== 'evidence-pack.dsse.json')) {
    const one = await main(['verify', '--key', join(SAMPLE, PUBLIC_KEY_FILE), '--envelope', join(SAMPLE, name), '--dir', SAMPLE]);
    assert.equal(one.code, 0, name);
  }
});

test('the sample pack carries the verdict checker, and it re-derives all 44 verdicts of the synthetic run', async () => {
  const checker = fileURLToPath(new URL('../verdict-check/verify_verdicts.py', import.meta.url));
  const check = args => new Promise(resolve => execFile('python3', ['-I', checker, '--key', join(SAMPLE, PUBLIC_KEY_FILE), ...args], { maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => resolve({ code: error ? error.code : 0, output: JSON.parse(stdout) })));
  assert.ok((await readdir(SAMPLE)).includes('verify_verdicts.py'));
  const one = await check(['--envelope', join(SAMPLE, 'run.json.dsse.json'), join(SAMPLE, 'run.json')]);
  assert.equal(one.code, 0);
  assert.equal(one.output.verdict, 'rederived');
  assert.deepEqual([one.output.summary.verdicts, one.output.summary.rederived, one.output.summary.notRederived], [44, 44, 0]);
  // The folder form re-derives the same verdicts. Its exit code also reflects the other files it lists, so it is not pinned here.
  const folder = await check(['--envelope', join(SAMPLE, 'evidence-pack.dsse.json'), '--dir', SAMPLE]);
  assert.deepEqual([folder.output.summary.verdicts, folder.output.summary.rederived, folder.output.summary.notRederived], [44, 44, 0]);
});

test('a real FreeTSA token from the sample pack checks against the pinned root, and fails against a test root', async () => {
  const token = await readFile(join(SAMPLE, 'evidence-pack.countersign.tsr'));
  const cs = JSON.parse(await readFile(join(SAMPLE, 'evidence-pack.countersign.dsse.json'), 'utf8'));
  const digestHex = sha256(Buffer.from(cs.signatures[0].sig, 'base64'));
  const { authorities } = readKeyset(await readFile(KEYSET_FILE));
  assert.equal(verifyTimestamp(token, { digest: digestHex, authorities }).tsa, 'freetsa.org');
  assert.throws(() => verifyTimestamp(token, { digest: digestHex, authorities: readKeyset(KEYSET).authorities }), /timestamp-untrusted/);
});

// Hostile and odd tokens from the review of this change: both verifiers must agree, and neither may crash or stall.
const derLength = n => { if (n < 128) return Buffer.from([n]); const b = []; for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 255); return Buffer.from([0x80 | b.length, ...b]); };
const TLV = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]); };
const DER_OID = text => { const [a, b, ...r] = text.split('.').map(Number), out = [a * 40 + b]; for (const x of r) { const bs = [x & 127]; for (let v = Math.floor(x / 128); v > 0; v = Math.floor(v / 128)) bs.unshift(0x80 | (v & 127)); out.push(...bs); } return TLV(6, Buffer.from(out)); };
const readTlv = (buf, pos) => { let l = buf[pos + 1], b = pos + 2; if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + buf[b + i]; b += n; } return { start: pos, body: b, end: b + l, tag: buf[pos] }; };
const readKids = (buf, node) => { const out = []; for (let p = node.body; p < node.end;) { const k = readTlv(buf, p); out.push(k); p = k.end; } return out; };
const RSA_SHA256 = TLV(0x30, DER_OID('1.2.840.113549.1.1.11'), Buffer.from([5, 0])), CN = TLV(0x30, TLV(0x31, TLV(0x30, DER_OID('2.5.4.3'), TLV(0x0c, Buffer.from('x')))));
const looseCertificate = (spki, notBefore = TLV(0x17, Buffer.from('250101000000Z'))) => TLV(0x30, TLV(0x30, TLV(0xa0, TLV(2, Buffer.from([2]))), TLV(2, Buffer.from([7])), RSA_SHA256, CN,
  TLV(0x30, notBefore, TLV(0x17, Buffer.from('350101000000Z'))), CN, spki), RSA_SHA256, TLV(3, Buffer.from([0, 1, 2, 3])));
// The token with one more certificate in its (unsigned) certificates set.
function withExtraCertificate(token, certificate) {
  const [status, info] = readKids(token, readTlv(token, 0)), [oid, held] = readKids(token, info), [signedData] = readKids(token, held);
  const parts = readKids(token, signedData).map(p => p.tag === 0xa0 ? TLV(0xa0, token.subarray(p.body, p.end), certificate) : token.subarray(p.start, p.end));
  return TLV(0x30, token.subarray(status.start, status.end), TLV(0x30, token.subarray(oid.start, oid.end), TLV(0xa0, TLV(0x30, ...parts))));
}

test('extra certificates, odd encodings and oversized keys get the same answer from both verifiers', async t => {
  const { generateKeyPairSync, randomBytes } = await import('node:crypto');
  const spki = (type, options) => generateKeyPairSync(type, options).publicKey.export({ type: 'spki', format: 'der' });
  // A certificate the token carries but does not sign with may hold any key: it is never read.
  for (const extra of [looseCertificate(spki('ed25519')), looseCertificate(spki('rsa', { modulusLength: 1024 }))])
    assert.equal((await bothVerify(t, { timestamp: withExtraCertificate(GOOD.timestamp, extra) })).node.verdict, 'verified');
  // Every certificate is still parsed, so a malformed time anywhere is refused.
  const year0 = looseCertificate(spki('ec', { namedCurve: 'prime256v1' }), TLV(0x18, Buffer.from('00000101000000Z')));
  assert.equal((await bothVerify(t, { timestamp: withExtraCertificate(GOOD.timestamp, year0) })).node.reason, 'timestamp-invalid');
  // An object identifier arc of thousands of bytes is refused, not a crash.
  const status = readKids(GOOD.timestamp, readTlv(GOOD.timestamp, 0))[0];
  const hugeOid = TLV(0x30, GOOD.timestamp.subarray(status.start, status.end), TLV(0x30, TLV(6, Buffer.concat([Buffer.from([0x2a]), Buffer.alloc(3000, 0xff), Buffer.from([0x7f])])), TLV(0xa0, TLV(0x30))));
  const huge = await bothVerify(t, { timestamp: hugeOid });
  assert.equal(huge.node.reason, 'timestamp-invalid');
  assert.equal(huge.code, 1);
  // A nonce the TSA encoded with a leading zero is the client's business, not the verifiers'.
  const nonce = await countersign(ENVELOPE, { stamp: stampWith(tsa, { nonce: Buffer.from([0, 5]) }) });
  assert.equal((await bothVerify(t, { countersignature: nonce.envelope, timestamp: nonce.timestamp })).node.verdict, 'verified');
  // A key set root given as an array is not a PEM string.
  const arrayRoot = JSON.parse(KEYSET); arrayRoot.timestampAuthorities[0].rootCertificate = [arrayRoot.timestampAuthorities[0].rootCertificate];
  assert.equal((await bothVerify(t, { keyset: JSON.stringify(arrayRoot) })).node.reason, 'keyset-invalid');
  // A signer certificate with a 16384-bit modulus and a 2400-bit exponent is refused before any RSA work, quickly.
  const modulus = randomBytes(2048); modulus[0] |= 0x80; modulus[2047] |= 1;
  const exponent = randomBytes(300); exponent[0] = 0x7f; exponent[299] |= 1;
  const SEQ = (...p) => TLV(0x30, ...p), SET = (...p) => TLV(0x31, ...p), ALG = o => SEQ(DER_OID(o), Buffer.from([5, 0]));
  const bigKey = SEQ(ALG('1.2.840.113549.1.1.1'), TLV(3, Buffer.from([0]), SEQ(TLV(2, Buffer.concat([Buffer.from([0]), modulus])), TLV(2, exponent))));
  const signerCert = SEQ(SEQ(TLV(0xa0, TLV(2, Buffer.from([2]))), TLV(2, Buffer.from([9])), RSA_SHA256, CN, SEQ(TLV(0x17, Buffer.from('250101000000Z')), TLV(0x17, Buffer.from('350101000000Z'))), CN, bigKey), RSA_SHA256, TLV(3, Buffer.from([0, 1])));
  const csSig = Buffer.from(JSON.parse(GOOD.envelope).signatures[0].sig, 'base64'), H = b => createHash('sha256').update(b).digest();
  const tst = SEQ(TLV(2, Buffer.from([1])), DER_OID('1.2.3'), SEQ(ALG('2.16.840.1.101.3.4.2.1'), TLV(4, H(csSig))), TLV(2, Buffer.from([1])), TLV(0x18, Buffer.from('20261029120000Z')));
  const attrs = [SEQ(DER_OID('1.2.840.113549.1.9.3'), SET(DER_OID('1.2.840.113549.1.9.16.1.4'))), SEQ(DER_OID('1.2.840.113549.1.9.4'), SET(TLV(4, H(tst)))),
    SEQ(DER_OID('1.2.840.113549.1.9.16.2.47'), SET(SEQ(SEQ(SEQ(TLV(4, H(signerCert)))))))];
  const sig = randomBytes(2048); sig[0] = 0;
  const signerInfo = SEQ(TLV(2, Buffer.from([1])), SEQ(CN, TLV(2, Buffer.from([9]))), ALG('2.16.840.1.101.3.4.2.1'), TLV(0xa0, ...attrs), RSA_SHA256, TLV(4, sig));
  const token = SEQ(SEQ(TLV(2, Buffer.from([0]))), SEQ(DER_OID('1.2.840.113549.1.7.2'), TLV(0xa0, SEQ(TLV(2, Buffer.from([3])), SET(ALG('2.16.840.1.101.3.4.2.1')),
    SEQ(DER_OID('1.2.840.113549.1.9.16.1.4'), TLV(0xa0, TLV(4, tst))), TLV(0xa0, signerCert), SET(signerInfo)))));
  const started = Date.now(), slow = await bothVerify(t, { timestamp: token });
  assert.equal(slow.node.reason, 'timestamp-invalid');
  assert.ok(Date.now() - started < 60000, 'refused without a long RSA computation');
});
