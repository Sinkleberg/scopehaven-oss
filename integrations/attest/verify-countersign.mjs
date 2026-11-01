// Scopehaven countersignature, verifier side (scopehaven-countersign/1).
// The operator's envelope (verify.mjs) is the first signature. ScopeHaven then countersigns hashes only: the SHA-256 of
// that envelope's statement, its signer's key id and the SHA-256 of its signature, never a file or a result. An RFC 3161
// timestamp from a public TSA covers the SHA-256 of the countersignature, so the time comes from neither the operator nor
// ScopeHaven. This module checks the countersignature against ScopeHaven's published key set (scopehaven-keys/1, served at
// https://scopehaven.dev/.well-known/scopehaven-keys.json), and the timestamp token against the TSA roots pinned in that
// set. It imports only Node built-ins and verify.mjs; verify_envelope.py repeats every check in Python.
//
// A countersignature shows that ScopeHaven's key signed these hashes, at the request of the named licence, before the
// TSA's time. It does not show that ScopeHaven ran the checks or that the results are correct. After a countersignature
// passes, negative controls (tampered payload and signature, an unpublished key, another statement, another first
// signature, a timestamp over another signature, a tampered token, no trusted TSA root, a revoked key) go through the same
// code and must be rejected; if any is accepted the verdict is self-check-failed.
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
// verify.mjs supplies only the DSSE pre-authentication encoding, the Ed25519 check and the key id rule it already applies.
import { PAYLOAD_TYPE, STATEMENT_TYPE, Rejected, keyIdOf, signatureValid, trustedKey } from './verify.mjs';

export const COUNTERSIGN_VERSION = 'scopehaven-countersign/1';
export const COUNTERSIGN_PREDICATE = 'https://scopehaven.dev/attestation/countersignature/v1';
export const COUNTERSIGN_MEANING = 'ScopeHaven countersigned the SHA-256 of this evidence statement and of its first signature, at the request of the named licence. ScopeHaven saw no file, row or result. The countersignature does not show that ScopeHaven ran the checks, or that the checks, the application or the results are correct.';
export const COUNTERSIGN_CLOCK = "ScopeHaven countersigner's clock; the RFC 3161 timestamp is the trusted time.";
export const KEYSET_SCHEMA = 'scopehaven-keys/1';
export const KEYSET_URL = 'https://scopehaven.dev/.well-known/scopehaven-keys.json';
export const COUNTERSIGNER = Object.freeze({ name: 'ScopeHaven', keys: KEYSET_URL });
export const STATEMENT_SUBJECT = 'evidence-statement';
// The countersigner's clock may run at most this far ahead of the TSA's.
export const CLOCK_SKEW_MS = 5 * 60 * 1000;
export const LICENCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/, VERSION = /^\d+\.\d+\.\d+$/;
const ISO = /^2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const isoTime = value => typeof value === 'string' && ISO.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
const KEY_STATUSES = ['active', 'interim', 'retired', 'revoked'];
const LIMITS = Object.freeze({ envelopeBytes: 64 * 1024, timestampBytes: 64 * 1024, keysetBytes: 256 * 1024 });
export const COUNTERSIGN_LIMITS = LIMITS;

const reject = (reason, detail) => { throw new Rejected(reason, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const bytesOf = value => Buffer.isBuffer(value) ? value : Buffer.from(String(value));
function strictBase64(text, reason) {
  if (typeof text !== 'string' || text.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) reject(reason, 'base64');
  const bytes = Buffer.from(text, 'base64');
  if (bytes.toString('base64') !== text) reject(reason, 'base64');
  return bytes;
}

// ---- DER (X.690), read strictly: definite lengths in their shortest form, no high tag numbers, nothing left over ----
const bad = detail => reject('timestamp-invalid', detail);
function tlv(buf, pos, limit) {
  if (pos + 2 > limit) bad('truncated DER');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) bad('high tag numbers are not used');
  let length = buf[pos + 1], body = pos + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n < 1 || n > 4 || body + n > limit || buf[body] === 0) bad('length is not in DER form');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[body + i];
    if (length < 128) bad('length is not in DER form');
    body += n;
  }
  const end = body + length;
  if (end > limit) bad('truncated DER');
  return { buf, tag, start: pos, body, end, get bytes() { return buf.subarray(pos, end); }, get value() { return buf.subarray(body, end); } };
}
const der = buf => { const node = tlv(buf, 0, buf.length); if (node.end !== buf.length) bad('trailing bytes after DER'); return node; };
function kids(node) {
  if (!(node.tag & 0x20)) bad('expected a constructed value');
  const out = [];
  for (let pos = node.body; pos < node.end;) { const kid = tlv(node.buf, pos, node.end); out.push(kid); pos = kid.end; }
  return out;
}
const expect = (node, tag, what) => { if (!node || node.tag !== tag) bad(`expected ${what}`); return node; };
const seq = (node, what = 'a SEQUENCE') => kids(expect(node, 0x30, what));
function oid(node) {
  const v = expect(node, 0x06, 'an OBJECT IDENTIFIER').value;
  if (!v.length || v[v.length - 1] & 0x80) bad('malformed OBJECT IDENTIFIER');
  const arcs = [];
  let n = 0n;
  for (let i = 0; i < v.length; i++) {
    if (n === 0n && v[i] === 0x80) bad('malformed OBJECT IDENTIFIER');
    n = (n << 7n) | BigInt(v[i] & 0x7f);
    if (n >= 1n << 64n) bad('OBJECT IDENTIFIER arc too large');
    if (!(v[i] & 0x80)) { arcs.push(n); n = 0n; }
  }
  const first = arcs[0] < 80n ? arcs[0] / 40n : 2n;
  return [first, arcs[0] - first * 40n, ...arcs.slice(1)].join('.');
}
function integer(node) {
  const v = expect(node, 0x02, 'an INTEGER').value;
  if (!v.length || (v.length > 1 && ((v[0] === 0 && !(v[1] & 0x80)) || (v[0] === 0xff && v[1] & 0x80)))) bad('malformed INTEGER');
  return v;
}
const octets = node => expect(node, 0x04, 'an OCTET STRING').value;
function bitString(node) {
  const v = expect(node, 0x03, 'a BIT STRING').value;
  if (!v.length || v[0] !== 0) bad('BIT STRING with unused bits');
  return v.subarray(1);
}
// UTCTime (YYMMDDHHMMSSZ) and GeneralizedTime (YYYYMMDDHHMMSS[.f]Z) as an ISO string with milliseconds; a fraction is cut
// to three digits, never rounded.
function time(node) {
  const text = node.value.toString('latin1');
  let m;
  if (node.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text))) m[1] = `${Number(m[1]) < 50 ? '20' : '19'}${m[1]}`;
  else if (node.tag !== 0x18 || !(m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z$/.exec(text))) bad('malformed time');
  if (Number(m[1]) < 1950) bad('malformed time');
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${((m[7] ?? '') + '000').slice(0, 3)}Z`;
  if (Number.isNaN(Date.parse(iso)) || new Date(iso).toISOString() !== iso) bad('malformed time');
  return iso;
}

const OID = Object.freeze({
  signedData: '1.2.840.113549.1.7.2', tstInfo: '1.2.840.113549.1.9.16.1.4', contentType: '1.2.840.113549.1.9.3', messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12', signingCertificateV2: '1.2.840.113549.1.9.16.2.47', rsaEncryption: '1.2.840.113549.1.1.1',
  sha1: '1.3.14.3.2.26', extKeyUsage: '2.5.29.37', timeStamping: '1.3.6.1.5.5.7.3.8',
});
const HASHES = Object.freeze({ '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' });
const SIGNATURES = Object.freeze({
  '1.2.840.113549.1.1.11': ['rsa', 'sha256'], '1.2.840.113549.1.1.12': ['rsa', 'sha384'], '1.2.840.113549.1.1.13': ['rsa', 'sha512'],
  '1.2.840.10045.4.3.2': ['ec', 'sha256'], '1.2.840.10045.4.3.3': ['ec', 'sha384'], '1.2.840.10045.4.3.4': ['ec', 'sha512'],
});
const CURVES = ['prime256v1', 'secp384r1'];
// RSA from 2048 to 16384 bits with an odd exponent of at most 64 bits, or ECDSA on P-256 or P-384, as verify_envelope.py reads them.
function supportedKey(key) {
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === 'rsa') return details.modulusLength >= 2048 && details.modulusLength <= 16384 && details.publicExponent >= 3n && details.publicExponent < 1n << 64n && details.publicExponent % 2n === 1n;
  return key.asymmetricKeyType === 'ec' && CURVES.includes(details.namedCurve);
}
// An AlgorithmIdentifier: its OID, with parameters absent or NULL.
function algorithm(node) {
  const parts = seq(node, 'an AlgorithmIdentifier');
  if (!parts.length || parts.length > 2 || (parts[1] && (parts[1].tag !== 0x05 || parts[1].value.length))) bad('unexpected algorithm parameters');
  return oid(parts[0]);
}
const hashName = node => HASHES[algorithm(node)] ?? bad('unsupported digest algorithm');
const digestOf = (name, bytes) => createHash(name).update(bytes).digest();
// RSA (PKCS #1 v1.5, at least 2048 bits) or ECDSA on P-256 or P-384 only, as verify_envelope.py implements them.
function signatureOk(publicKey, [kind, hash], data, sig) {
  if (publicKey.asymmetricKeyType !== kind || !supportedKey(publicKey)) return false;
  try { return verify(hash, data, kind === 'ec' ? { key: publicKey, dsaEncoding: 'der' } : publicKey, sig) === true; } catch { return false; }
}

// An X.509 certificate, read as far as the checks below need.
function certificate(bytes) {
  const node = der(bytes), [tbsNode, algNode, sigNode, ...extra] = seq(node, 'a certificate');
  if (extra.length || !sigNode) bad('malformed certificate');
  const tbs = seq(tbsNode, 'a TBSCertificate');
  let i = tbs[0]?.tag === 0xa0 ? 1 : 0;
  const [serial, innerAlg, issuer, validity, subject, spki] = tbs.slice(i, i + 6);
  if (!spki) bad('malformed certificate');
  const signatureAlgorithm = algorithm(algNode);
  if (algorithm(innerAlg) !== signatureAlgorithm) bad('certificate signature algorithms differ');
  const [notBefore, notAfter, ...rest] = seq(validity, 'a Validity');
  if (!notAfter || rest.length) bad('malformed validity');
  expect(issuer, 0x30, 'a Name'); expect(subject, 0x30, 'a Name');
  const extensions = new Map();
  for (const node of tbs.slice(i + 6)) {
    if (node.tag !== 0xa3) continue;
    const [list, ...more] = kids(node);
    if (more.length) bad('malformed extensions');
    for (const ext of seq(list)) {
      const parts = seq(ext), id = oid(parts[0]);
      const critical = parts.length === 3 ? (expect(parts[1], 0x01, 'a BOOLEAN').value.length === 1 && parts[1].value[0] === 0xff) : false;
      if (parts.length < 2 || parts.length > 3 || extensions.has(id)) bad('malformed extension');
      extensions.set(id, { critical, value: octets(parts[parts.length - 1]) });
    }
  }
  expect(spki, 0x30, 'a SubjectPublicKeyInfo');
  let key;
  // The key is read only for the signer and the roots: other certificates in a token are not signed over and may hold any key.
  const publicKey = () => {
    if (key) return key;
    try { key = createPublicKey({ key: Buffer.from(spki.bytes), format: 'der', type: 'spki' }); } catch { bad('unsupported public key'); }
    if (!supportedKey(key)) bad('unsupported public key');
    return key;
  };
  return { der: Buffer.from(bytes), tbs: tbsNode.bytes, signatureAlgorithm, signature: bitString(sigNode), serial: Buffer.from(integer(serial)),
    issuer: Buffer.from(issuer.bytes), subject: Buffer.from(subject.bytes), notBefore: time(notBefore), notAfter: time(notAfter), extensions, publicKey };
}
const within = (cert, iso) => cert.notBefore <= iso && iso <= cert.notAfter;
const issuedBy = (cert, root) => cert.issuer.equals(root.subject) && SIGNATURES[cert.signatureAlgorithm] !== undefined
  && signatureOk(root.publicKey(), SIGNATURES[cert.signatureAlgorithm], cert.tbs, cert.signature);

// A PEM certificate as the key set carries it: one block, with only blank lines or spaces around it.
export function certificateFromPem(text) {
  if (typeof text !== 'string') return null;
  const pem = String(text).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
  const m = /^-----BEGIN CERTIFICATE-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END CERTIFICATE-----$/.exec(pem);
  if (!m) return null;
  const bytes = Buffer.from(m[1].replace(/\r?\n/g, ''), 'base64');
  return bytes.toString('base64') === m[1].replace(/\r?\n/g, '') ? bytes : null;
}

// An RFC 3161 TimeStampResp (DER). Checks, in order: a granted status; a SignedData token over a TSTInfo; one signer,
// named by issuer and serial among the token's certificates; signed attributes with the TSTInfo content type, its digest
// and an ESS signing-certificate hash of that signer's certificate; the signature over those attributes; the signer's
// certificate, which must be for time stamping only (critical extended key usage), valid at the stamped time and issued by
// a root pinned in the key set that is also valid then; and last, that the token stamps the SHA-256 `digest`.
// authorities: [{ name, root: certificate() }].
export function verifyTimestamp(token, { digest, authorities }) {
  if (!Buffer.isBuffer(token) || token.length > LIMITS.timestampBytes) bad('not a timestamp response of at most 64 KiB');
  const response = seq(der(token), 'a TimeStampResp');
  if (response.length !== 2) bad('no timestamp token');
  const status = seq(response[0], 'a PKIStatusInfo'), code = integer(status[0]);
  if (code.length !== 1 || code[0] > 1) bad('the TSA did not grant the request');
  const contentInfo = seq(response[1], 'a ContentInfo');
  if (contentInfo.length !== 2 || oid(contentInfo[0]) !== OID.signedData) bad('not a SignedData token');
  const [signedDataNode, ...extra] = kids(expect(contentInfo[1], 0xa0, 'explicit content'));
  if (extra.length) bad('malformed token');
  const signedData = seq(signedDataNode, 'a SignedData');
  let i = 3;
  const [, , encap] = signedData, certs = [];
  if (signedData[i]?.tag === 0xa0) for (const node of kids(signedData[i++])) certs.push(certificate(node.bytes));
  if (signedData[i]?.tag === 0xa1) i++;
  if (i !== signedData.length - 1) bad('malformed SignedData');
  const encapParts = seq(encap, 'an EncapsulatedContentInfo');
  if (encapParts.length !== 2 || oid(encapParts[0]) !== OID.tstInfo) bad('the token does not hold a TSTInfo');
  const [eContentNode, ...more] = kids(expect(encapParts[1], 0xa0, 'explicit content'));
  if (more.length) bad('malformed token');
  const eContent = octets(eContentNode);
  const signers = kids(expect(signedData[i], 0x31, 'a SET of signers'));
  if (signers.length !== 1) bad('exactly one signer is accepted');
  const si = seq(signers[0], 'a SignerInfo');
  if (si.length < 6 || si.length > 7 || si[3].tag !== 0xa0) bad('the signer has no signed attributes');
  const [sid, digestAlg, attrsNode, sigAlg, sigNode] = si.slice(1);
  const sidParts = seq(sid, 'issuer and serial number (a signer named by key id is not supported)');
  if (sidParts.length !== 2) bad('malformed signer id');
  const sidIssuer = expect(sidParts[0], 0x30, 'a Name').bytes, sidSerial = integer(sidParts[1]);
  const signer = certs.find(cert => cert.issuer.equals(sidIssuer) && cert.serial.equals(sidSerial)) ?? bad("the token does not carry its signer's certificate");
  const hash = hashName(digestAlg), attrs = new Map();
  for (const attr of kids(attrsNode)) {
    const parts = seq(attr), id = oid(parts[0]), values = parts.length === 2 ? kids(expect(parts[1], 0x31, 'a SET of values')) : [];
    if (values.length !== 1 || attrs.has(id)) bad('malformed signed attribute');
    attrs.set(id, values[0]);
  }
  if (!attrs.has(OID.contentType) || oid(attrs.get(OID.contentType)) !== OID.tstInfo) bad('the signed content type is not TSTInfo');
  if (!attrs.has(OID.messageDigest) || !octets(attrs.get(OID.messageDigest)).equals(digestOf(hash, eContent))) bad('the signed digest does not match the TSTInfo');
  // ESS: the signed attributes name the signer's certificate by hash (RFC 5035 v2, or v1 with SHA-1).
  const v2 = attrs.get(OID.signingCertificateV2), v1 = attrs.get(OID.signingCertificate);
  if (!v1 && !v2) bad('no signing-certificate attribute');
  const [certId] = seq(seq(v2 ?? v1)[0]);
  const idParts = seq(certId);
  const essHash = v2 && idParts[0]?.tag === 0x30 ? hashName(idParts.shift()) : v2 ? 'sha256' : 'sha1';
  if (!octets(idParts[0]).equals(digestOf(essHash, signer.der))) bad('the signing-certificate attribute names another certificate');
  const sigAlgOid = algorithm(sigAlg), kind = sigAlgOid === OID.rsaEncryption ? ['rsa', hash] : SIGNATURES[sigAlgOid] ?? bad('unsupported signature algorithm');
  const signedBytes = Buffer.concat([Buffer.from([0x31]), attrsNode.bytes.subarray(1)]);
  if (!signatureOk(signer.publicKey(), kind, signedBytes, octets(sigNode))) bad("the token's signature does not verify");
  // TSTInfo: version 1, policy, message imprint, serial number, generation time.
  const tst = seq(der(Buffer.from(eContent)), 'a TSTInfo');
  const version = integer(tst[0]);
  if (version.length !== 1 || version[0] !== 1 || tst.length < 5) bad('malformed TSTInfo');
  const policy = oid(tst[1]), imprint = seq(tst[2], 'a MessageImprint'), serialNumber = integer(tst[3]).toString('hex');
  const genTime = time(expect(tst[4], 0x18, 'a GeneralizedTime'));
  const nonceNode = tst.slice(5).find(node => node.tag === 0x02), nonce = nonceNode ? nonceNode.value.toString('hex') : null; // read raw: only the client compares it
  const eku = signer.extensions.get(OID.extKeyUsage);
  if (!eku?.critical) bad("the signer's certificate is not marked for time stamping only");
  const purposes = seq(der(Buffer.from(eku.value)));
  if (purposes.length !== 1 || oid(purposes[0]) !== OID.timeStamping) bad("the signer's certificate is not marked for time stamping only");
  if (!within(signer, genTime)) bad("the signer's certificate was not valid at the stamped time");
  const authority = authorities.find(a => within(a.root, genTime) && issuedBy(signer, a.root));
  if (!authority) reject('timestamp-untrusted', 'no TSA root in the key set issued this token');
  if (imprint.length !== 2 || hashName(imprint[0]) !== 'sha256' || octets(imprint[1]).toString('hex') !== digest)
    reject('timestamp-imprint-mismatch', 'the token stamps another digest');
  return { tsa: authority.name, genTime, serialNumber, policy, nonce, eContentOffset: eContentNode.body };
}

// ---- The key set (scopehaven-keys/1) ----
// A malformed set, a key whose id is not the SHA-256 of its public key, or a TSA root whose sha256 differs, is refused
// (keyset-invalid): the set is the trust root, so it is never read loosely.
export function readKeyset(text) {
  let set;
  try { set = JSON.parse(utf8.decode(bytesOf(text))); } catch { reject('keyset-invalid', 'not JSON'); }
  if (!exactKeys(set, ['schema', 'publisher', 'url', 'updated', 'countersigningKeys', 'timestampAuthorities', 'policy']) || set.schema !== KEYSET_SCHEMA
    || set.publisher !== COUNTERSIGNER.name || set.url !== KEYSET_URL || !isoTime(set.updated) || !exactKeys(set.policy, ['rotation', 'revocation'])
    || typeof set.policy.rotation !== 'string' || typeof set.policy.revocation !== 'string'
    || !Array.isArray(set.countersigningKeys) || !Array.isArray(set.timestampAuthorities)) reject('keyset-invalid', 'not a scopehaven-keys/1 document');
  const keys = new Map();
  for (const entry of set.countersigningKeys) {
    if (!exactKeys(entry, ['keyid', 'publicKey', 'status', 'notBefore', 'notAfter', 'revokedAt', 'note']) || !HEX64.test(entry.keyid) || keys.has(entry.keyid)
      || !KEY_STATUSES.includes(entry.status) || !isoTime(entry.notBefore) || typeof entry.note !== 'string'
      || ![entry.notAfter, entry.revokedAt].every(v => v === null || isoTime(v)) || (entry.status === 'revoked') !== (entry.revokedAt !== null))
      reject('keyset-invalid', 'malformed countersigning key');
    let key;
    try { key = trustedKey(entry.publicKey); } catch { reject('keyset-invalid', `key ${entry.keyid} is not an Ed25519 public key`); }
    if (keyIdOf(key) !== entry.keyid) reject('keyset-invalid', `key ${entry.keyid} is not the SHA-256 of its public key`);
    keys.set(entry.keyid, { ...entry, key });
  }
  const authorities = [];
  for (const entry of set.timestampAuthorities) {
    if (!exactKeys(entry, ['name', 'url', 'rootSha256', 'rootCertificate']) || typeof entry.name !== 'string' || typeof entry.url !== 'string' || !HEX64.test(entry.rootSha256))
      reject('keyset-invalid', 'malformed timestamp authority');
    const bytes = certificateFromPem(entry.rootCertificate);
    if (!bytes || sha256(bytes) !== entry.rootSha256) reject('keyset-invalid', `the ${entry.name} root is not the certificate its sha256 names`);
    let root;
    try { root = certificate(bytes); root.publicKey(); } catch (error) { if (error instanceof Rejected) reject('keyset-invalid', `the ${entry.name} root is not a certificate`); throw error; }
    authorities.push({ name: entry.name, url: entry.url, root });
  }
  return { keys, authorities };
}
// A key countersigns validly only when the TSA's time lies in its window and before any revocation: a signature stamped
// before a key was revoked stays valid, one stamped after does not.
function keyValidAt(entry, genTime) {
  if (entry.revokedAt !== null && genTime >= entry.revokedAt) reject('countersign-key-revoked', `key ${entry.keyid} was revoked at ${entry.revokedAt}`);
  if (genTime < entry.notBefore || (entry.notAfter !== null && genTime >= entry.notAfter)) reject('countersign-key-not-valid', `key ${entry.keyid} was not in use at ${genTime}`);
}

// ---- The countersignature envelope ----
// The first envelope's statement and signature, read without trust: the caller has verified it already.
export function firstSignature(envelope) {
  const env = JSON.parse(utf8.decode(bytesOf(envelope))), [entry] = env.signatures;
  return { payloadType: env.payloadType, payload: Buffer.from(env.payload, 'base64'), keyid: entry.keyid, sig: Buffer.from(entry.sig, 'base64') };
}
function countersignEnvelope(bytes, keys) {
  if (bytes.length > LIMITS.envelopeBytes) reject('countersign-shape', 'envelope size');
  let env;
  try { env = JSON.parse(utf8.decode(bytes)); } catch { reject('countersign-shape', 'not JSON'); }
  if (!exactKeys(env, ['payload', 'payloadType', 'signatures']) || env.payloadType !== PAYLOAD_TYPE || !Array.isArray(env.signatures) || env.signatures.length !== 1)
    reject('countersign-shape', 'not a DSSE envelope with one signature');
  const [entry] = env.signatures;
  if (!exactKeys(entry, ['keyid', 'sig']) || typeof entry.keyid !== 'string') reject('countersign-shape', 'signature');
  const payload = strictBase64(env.payload, 'countersign-shape'), sig = strictBase64(entry.sig, 'countersign-shape');
  const key = keys.get(entry.keyid) ?? reject('countersign-key-unknown', 'signed by a key that is not in ScopeHaven\'s published key set');
  return { type: env.payloadType, payload, sig, key };
}
function parseCountersignStatement(payload) {
  let text, statement;
  try { text = utf8.decode(payload); statement = JSON.parse(text); } catch { reject('countersign-shape', 'payload is not JSON'); }
  if (JSON.stringify(statement) !== text) reject('countersign-shape', 'payload is not canonical');
  if (!exactKeys(statement, ['_type', 'subject', 'predicateType', 'predicate']) || statement._type !== STATEMENT_TYPE || statement.predicateType !== COUNTERSIGN_PREDICATE)
    reject('countersign-shape', 'not a countersignature statement');
  const { subject, predicate } = statement;
  if (!Array.isArray(subject) || subject.length !== 1 || !exactKeys(subject[0], ['name', 'digest']) || subject[0].name !== STATEMENT_SUBJECT
    || !exactKeys(subject[0].digest, ['sha256']) || !HEX64.test(subject[0].digest.sha256)) reject('countersign-shape', 'subject');
  if (!exactKeys(predicate, ['meaning', 'clock', 'countersigner', 'firstSignature', 'request', 'signedAt']) || predicate.meaning !== COUNTERSIGN_MEANING
    || predicate.clock !== COUNTERSIGN_CLOCK || !exactKeys(predicate.countersigner, ['name', 'keys']) || predicate.countersigner.name !== COUNTERSIGNER.name
    || predicate.countersigner.keys !== COUNTERSIGNER.keys || !isoTime(predicate.signedAt)) reject('countersign-shape', 'predicate');
  const first = predicate.firstSignature, request = predicate.request;
  if (!exactKeys(first, ['keyid', 'sigSha256', 'payloadType']) || !HEX64.test(first.keyid) || !HEX64.test(first.sigSha256) || first.payloadType !== PAYLOAD_TYPE)
    reject('countersign-shape', 'firstSignature');
  if (!exactKeys(request, ['licenceId', 'release', 'nonce']) || typeof request.licenceId !== 'string' || !LICENCE_ID.test(request.licenceId)
    || typeof request.release !== 'string' || !VERSION.test(request.release) || typeof request.nonce !== 'string' || !HEX32.test(request.nonce))
    reject('countersign-shape', 'request');
  return statement;
}
// The countersignature names this first envelope: its statement's SHA-256, its signer and the SHA-256 of its signature.
function bind(statement, first) {
  if (statement.subject[0].digest.sha256 !== sha256(first.payload)) reject('countersign-subject-mismatch', 'the countersignature is over another evidence statement');
  const named = statement.predicate.firstSignature;
  if (named.keyid !== first.keyid || named.sigSha256 !== sha256(first.sig) || named.payloadType !== first.payloadType)
    reject('countersign-signer-mismatch', 'the countersignature names another first signature');
}
function examine({ countersignature, timestamp, first, keyset }, checkSignature) {
  const cs = countersignEnvelope(countersignature, keyset.keys);
  if (cs.sig.length !== 64 || !checkSignature(cs.key.key, cs.type, cs.payload, cs.sig)) reject('countersign-signature-invalid');
  const statement = parseCountersignStatement(cs.payload);
  bind(statement, first);
  const stamp = verifyTimestamp(timestamp, { digest: sha256(cs.sig), authorities: keyset.authorities });
  keyValidAt(cs.key, stamp.genTime);
  if (Date.parse(statement.predicate.signedAt) > Date.parse(stamp.genTime) + CLOCK_SKEW_MS)
    reject('countersign-time-inconsistent', 'the countersigner\'s clock is ahead of the TSA\'s by more than five minutes');
  return { cs, statement, stamp };
}

function negativeControls({ cs, statement, stamp }, { countersignature, timestamp, first, keyset }, checkSignature) {
  const flip = bytes => { const copy = Buffer.from(bytes.length ? bytes : [0]); copy[copy.length >> 1] ^= 1; return copy; };
  const passes = attempt => { try { attempt(); return true; } catch (error) { if (error instanceof Rejected) return false; throw error; } };
  // The same envelope naming a fresh key's id, and the token with one byte of its TSTInfo changed.
  const unpublished = JSON.parse(utf8.decode(countersignature));
  unpublished.signatures[0].keyid = keyIdOf(generateKeyPairSync('ed25519').publicKey);
  const tampered = Buffer.from(timestamp); tampered[stamp.eContentOffset + 4] ^= 1;
  const controls = [
    ['countersign-payload-tampered', () => checkSignature(cs.key.key, cs.type, flip(cs.payload), cs.sig)],
    ['countersign-signature-tampered', () => checkSignature(cs.key.key, cs.type, cs.payload, flip(cs.sig))],
    ['countersign-unpublished-key', () => passes(() => countersignEnvelope(Buffer.from(JSON.stringify(unpublished)), keyset.keys))],
    ['countersign-other-statement', () => passes(() => bind(statement, { ...first, payload: flip(first.payload) }))],
    ['countersign-other-first-signature', () => passes(() => bind(statement, { ...first, sig: flip(first.sig) }))],
    ['timestamp-other-signature', () => passes(() => verifyTimestamp(timestamp, { digest: sha256(flip(cs.sig)), authorities: keyset.authorities }))],
    ['timestamp-token-tampered', () => passes(() => verifyTimestamp(tampered, { digest: sha256(cs.sig), authorities: keyset.authorities }))],
    ['timestamp-untrusted-root', () => passes(() => verifyTimestamp(timestamp, { digest: sha256(cs.sig), authorities: [] }))],
    ['countersign-key-revoked', () => passes(() => keyValidAt({ ...cs.key, revokedAt: stamp.genTime }, stamp.genTime))],
  ];
  return controls.map(([id, attempt]) => {
    let accepted;
    try { accepted = attempt() === true; } catch (error) { if (!(error instanceof Rejected)) throw error; accepted = false; }
    return { id, expected: 'rejected', observed: accepted ? 'accepted' : 'rejected' };
  });
}

// envelope: the first (operator) envelope, already verified with verify.mjs. countersignature and timestamp are the bytes of
// NAME.countersign.dsse.json and NAME.countersign.tsr (undefined when absent); keyset is the published key set's bytes.
// `checkSignature` is replaceable only so tests can prove a verifier that accepts everything is caught.
export function verifyCountersignature({ envelope, countersignature, timestamp, keyset }, { checkSignature = signatureValid } = {}) {
  const result = (verdict, fields) => ({ countersign: COUNTERSIGN_VERSION, verified: verdict === 'verified', verdict, ...fields });
  let inputs, checked;
  try {
    if (countersignature === undefined) reject('countersign-missing', 'no countersignature was given');
    if (timestamp === undefined) reject('timestamp-missing', 'no timestamp token was given');
    inputs = { countersignature: bytesOf(countersignature), timestamp: bytesOf(timestamp), first: firstSignature(envelope), keyset: readKeyset(keyset) };
    checked = examine(inputs, checkSignature);
  } catch (error) {
    if (!(error instanceof Rejected)) throw error;
    return result('rejected', { reason: error.reason, detail: error.message, selfChecks: [] });
  }
  const selfChecks = negativeControls(checked, inputs, checkSignature), accepted = selfChecks.filter(c => c.observed !== 'rejected').map(c => c.id);
  const { cs, statement, stamp } = checked, { predicate } = statement;
  return result(accepted.length ? 'self-check-failed' : 'verified', {
    reason: accepted.length ? 'negative-control-accepted' : null,
    detail: accepted.length ? `This verifier accepted tampered input (${accepted.join(', ')}); do not rely on it.` : null,
    keyid: cs.key.keyid, keyStatus: cs.key.status, meaning: predicate.meaning, statementSha256: statement.subject[0].digest.sha256,
    firstSignerKeyid: predicate.firstSignature.keyid, request: predicate.request, signedAt: predicate.signedAt, clock: predicate.clock,
    timestamp: { tsa: stamp.tsa, genTime: stamp.genTime, serialNumber: stamp.serialNumber, policy: stamp.policy }, selfChecks });
}
// Folds a countersignature result into the first envelope's: both must verify for the whole to verify.
export function combined(first, countersignature) {
  if (!first.verified) return { ...first, countersignature: null };
  if (countersignature.verified) return { ...first, countersignature };
  return { ...first, verified: false, verdict: countersignature.verdict, reason: countersignature.reason, detail: countersignature.detail, countersignature };
}
