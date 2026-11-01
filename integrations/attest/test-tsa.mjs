// A test-only RFC 3161 time-stamping authority, for the countersignature tests. It makes its own root (RSA 2048) and TSA
// certificate (ECDSA P-256, extended key usage time stamping only, critical) in memory on every run, so no key is ever
// written to disk or committed, and it answers TimeStampReq bytes over loopback HTTP or directly. Never trust its root
// outside a test: tests put it in a test key set only. Options make the faults the verifiers must reject.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';

function length(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, ...parts) => { const body = Buffer.concat(parts.flat()); return Buffer.concat([Buffer.from([tag]), length(body.length), body]); };
const SEQ = (...parts) => tlv(0x30, ...parts);
// DER SET OF: elements in the order of their encodings.
const SET = (...parts) => tlv(0x31, ...parts.flat().sort(Buffer.compare));
function OID(text) {
  const [a, b, ...rest] = text.split('.').map(Number), out = [a * 40 + b];
  for (const arc of rest) {
    const bytes = [arc & 0x7f];
    for (let v = Math.floor(arc / 128); v > 0; v = Math.floor(v / 128)) bytes.unshift(0x80 | (v & 0x7f));
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
}
function INT(value) {
  let bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value.toString(16).padStart(2 * Math.ceil(value.toString(16).length / 2), '0'), 'hex');
  while (bytes.length > 1 && bytes[0] === 0 && !(bytes[1] & 0x80)) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(0x02, bytes);
}
const NULL = Buffer.from([0x05, 0x00]), OCTETS = bytes => tlv(0x04, bytes), BITS = bytes => tlv(0x03, Buffer.from([0]), bytes);
const BOOL = value => tlv(0x01, Buffer.from([value ? 0xff : 0]));
const pad = (n, w = 2) => String(n).padStart(w, '0');
const UTC = date => tlv(0x17, Buffer.from(`${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`));
const GENERALIZED = date => tlv(0x18, Buffer.from(`${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`));
const NAME = cn => SEQ(SET(SEQ(OID('2.5.4.3'), tlv(0x0c, Buffer.from(cn)))));
const ALG = (oid, params = true) => SEQ(OID(oid), ...(params ? [NULL] : []));
const SHA256_RSA = '1.2.840.113549.1.1.11', ECDSA_SHA256 = '1.2.840.10045.4.3.2', SHA256 = '2.16.840.1.101.3.4.2.1';
const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const DAY = 86400000;

function certificate({ serial, issuer, subject, notBefore, notAfter, publicKey, extensions, signer }) {
  const tbs = SEQ(tlv(0xa0, INT(2)), INT(serial), ALG(SHA256_RSA), issuer, SEQ(UTC(notBefore), UTC(notAfter)), subject,
    publicKey.export({ type: 'spki', format: 'der' }), tlv(0xa3, SEQ(...extensions)));
  return SEQ(tbs, ALG(SHA256_RSA), BITS(sign('sha256', tbs, signer)));
}

// One test TSA. name: its key-set name. leafExtendedKeyUsage: 'critical' (default), 'not-critical' or 'none'.
export function createTestTsa({ name = 'test-tsa.local', leafExtendedKeyUsage = 'critical', leafValidDays = 3650, now = new Date() } = {}) {
  const root = generateKeyPairSync('rsa', { modulusLength: 2048 }), leaf = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const rootName = NAME(`${name} test root (never trusted outside tests)`), leafName = NAME(`${name} test TSA`);
  const start = new Date(now.getTime() - DAY);
  const rootDer = certificate({ serial: 1, issuer: rootName, subject: rootName, notBefore: start, notAfter: new Date(start.getTime() + 3650 * DAY), publicKey: root.publicKey,
    extensions: [SEQ(OID('2.5.29.19'), BOOL(true), OCTETS(SEQ(BOOL(true))))], signer: root.privateKey });
  const eku = leafExtendedKeyUsage === 'none' ? [] : [SEQ(OID('2.5.29.37'), ...(leafExtendedKeyUsage === 'critical' ? [BOOL(true)] : []), OCTETS(SEQ(OID('1.3.6.1.5.5.7.3.8'))))];
  const leafSerial = randomBytes(8);
  const leafDer = certificate({ serial: leafSerial, issuer: rootName, subject: leafName, notBefore: start, notAfter: new Date(start.getTime() + leafValidDays * DAY), publicKey: leaf.publicKey,
    extensions: eku, signer: root.privateKey });
  let serialNumber = 1;

  // A TimeStampResp over a SHA-256 digest (Buffer), stamped at genTime.
  function stamp(digest, { nonce, genTime = new Date() } = {}) {
    const tst = SEQ(INT(1), OID('1.3.6.1.4.1.99999.1'), SEQ(ALG(SHA256), OCTETS(digest)), INT(serialNumber++), GENERALIZED(genTime), ...(nonce ? [tlv(0x02, nonce)] : []));
    const attrs = [SEQ(OID('1.2.840.113549.1.9.3'), SET(OID('1.2.840.113549.1.9.16.1.4'))), SEQ(OID('1.2.840.113549.1.9.4'), SET(OCTETS(sha256(tst)))),
      SEQ(OID('1.2.840.113549.1.9.16.2.47'), SET(SEQ(SEQ(SEQ(OCTETS(sha256(leafDer)))))))];
    const signed = SET(...attrs), signature = sign('sha256', signed, { key: leaf.privateKey, dsaEncoding: 'der' });
    const signerInfo = SEQ(INT(1), SEQ(rootName, INT(leafSerial)), ALG(SHA256), tlv(0xa0, ...[...attrs].sort(Buffer.compare)), ALG(ECDSA_SHA256, false), OCTETS(signature));
    const signedData = SEQ(INT(3), SET(ALG(SHA256)), SEQ(OID('1.2.840.113549.1.9.16.1.4'), tlv(0xa0, OCTETS(tst))), tlv(0xa0, leafDer, rootDer), SET(signerInfo));
    return SEQ(SEQ(INT(0)), SEQ(OID('1.2.840.113549.1.7.2'), tlv(0xa0, signedData)));
  }
  // The digest and nonce of a TimeStampReq as countersign.mjs writes it (version, imprint, nonce, certReq).
  function respond(query, options = {}) {
    const digestAt = query.indexOf(Buffer.from([0x04, 0x20])), digest = query.subarray(digestAt + 2, digestAt + 34);
    const nonceAt = digestAt + 34, nonce = query[nonceAt] === 0x02 ? query.subarray(nonceAt + 2, nonceAt + 2 + query[nonceAt + 1]) : undefined;
    return stamp(digest, { nonce, ...options });
  }
  // A loopback HTTP TSA; resolves to its URL. Closed with server.close().
  async function listen(options = {}) {
    const server = createServer((req, res) => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => { const reply = respond(Buffer.concat(chunks), options); res.writeHead(200, { 'content-type': 'application/timestamp-reply' }); res.end(reply); });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return { server, url: `http://127.0.0.1:${server.address().port}/tsr` };
  }
  const authority = url => ({ name, url, rootSha256: sha256(rootDer).toString('hex'), rootCertificate: pem('CERTIFICATE', rootDer) });
  return { name, rootDer, leafDer, stamp, respond, listen, authority };
}
