// Scopehaven countersignature, signer side (scopehaven-countersign/1).
// The operator signs evidence with their own key (sign.mjs). The countersignature is a second, ScopeHaven-held signature
// over hashes only, so nothing of the operator's leaves their machine but those hashes:
//   1. countersignRequest() builds the request from the operator's envelope: the SHA-256 of its statement, its signer's key
//      id and the SHA-256 of its signature, plus a licence id, the release and a nonce. That body is all that is sent.
//   2. countersignService() is the countersigning endpoint. It takes exactly that body, signs an in-toto statement over the
//      hashes with ScopeHaven's key, then has a public RFC 3161 TSA stamp the SHA-256 of that signature (the TSA sees only
//      that digest). In this build it runs locally with ScopeHaven's key; a hosted endpoint takes the same body and returns
//      the same two files. It checks no licence yet.
//   3. requestTimestamp() is the RFC 3161 client (HTTP POST of a DER TimeStampReq).
// Nothing is returned unless the result verifies with verify-countersign.mjs against the given key set.
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, KeyObject } from 'node:crypto';
import { PAYLOAD_TYPE, STATEMENT_TYPE, keyIdOf, pae } from './verify.mjs';
import { COUNTERSIGNER, COUNTERSIGN_CLOCK, COUNTERSIGN_LIMITS, COUNTERSIGN_MEANING, COUNTERSIGN_PREDICATE, LICENCE_ID, STATEMENT_SUBJECT,
  firstSignature, readKeyset, verifyCountersignature, verifyTimestamp } from './verify-countersign.mjs';

export const REQUEST_SCHEMA = 'scopehaven-countersign-request/1';
// Every field of a request, and no other: nothing but hashes, the licence, the release and a nonce can be sent.
export const REQUEST_FIELDS = Object.freeze(['request', 'licenceId', 'release', 'statementSha256', 'signerKeyid', 'signatureSha256', 'nonce']);
const HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/, VERSION = /^\d+\.\d+\.\d+$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// The request for one operator envelope (already verified by the caller).
export function countersignRequest(envelope, { licenceId, release, nonce = randomBytes(16).toString('hex') }) {
  const first = firstSignature(envelope);
  const request = { request: REQUEST_SCHEMA, licenceId, release, statementSha256: sha256(first.payload), signerKeyid: first.keyid, signatureSha256: sha256(first.sig), nonce };
  return checkRequest(request);
}
function checkRequest(request) {
  const plain = request !== null && typeof request === 'object' && !Array.isArray(request);
  if (!plain || Object.keys(request).length !== REQUEST_FIELDS.length || !REQUEST_FIELDS.every(key => Object.hasOwn(request, key)) || request.request !== REQUEST_SCHEMA
    || typeof request.licenceId !== 'string' || !LICENCE_ID.test(request.licenceId) || typeof request.release !== 'string' || !VERSION.test(request.release)
    || ![request.statementSha256, request.signerKeyid, request.signatureSha256].every(v => typeof v === 'string' && HEX64.test(v))
    || typeof request.nonce !== 'string' || !HEX32.test(request.nonce))
    throw new Error(`A countersign request has exactly the fields ${REQUEST_FIELDS.join(', ')}: hashes as 64 lowercase hex, a licence id, an x.y.z release and a 32-hex nonce.`);
  return request;
}

// The countersigning endpoint. body: the request as JSON text. timestamp: async (sha256 hex) => TimeStampResp bytes.
export async function countersignService(body, { privateKey, timestamp, now = new Date() }) {
  let request;
  try { request = JSON.parse(String(body)); } catch { throw new Error('The countersign request is not JSON.'); }
  checkRequest(request);
  let key = privateKey;
  if (!(key instanceof KeyObject)) key = createPrivateKey(key);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('Countersigning needs ScopeHaven\'s Ed25519 private key.');
  const statement = { _type: STATEMENT_TYPE, subject: [{ name: STATEMENT_SUBJECT, digest: { sha256: request.statementSha256 } }], predicateType: COUNTERSIGN_PREDICATE,
    predicate: { meaning: COUNTERSIGN_MEANING, clock: COUNTERSIGN_CLOCK, countersigner: { ...COUNTERSIGNER },
      firstSignature: { keyid: request.signerKeyid, sigSha256: request.signatureSha256, payloadType: PAYLOAD_TYPE },
      request: { licenceId: request.licenceId, release: request.release, nonce: request.nonce }, signedAt: now.toISOString() } };
  const payload = Buffer.from(JSON.stringify(statement)), sig = sign(null, pae(PAYLOAD_TYPE, payload), key);
  const envelope = `${JSON.stringify({ payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'), signatures: [{ keyid: keyIdOf(createPublicKey(key)), sig: sig.toString('base64') }] }, null, 2)}\n`;
  return { envelope, timestamp: await timestamp(sha256(sig)) };
}

// ---- RFC 3161 client ----
function derLength(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const der = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]); };
// A random nonce as a positive INTEGER in its shortest form.
const nonceInteger = nonce => { const n = Buffer.from(nonce); n[0] &= 0x7f; if (n[0] === 0) n[0] = 1; return n; };
const SHA256_ALGORITHM = Buffer.from('300d06096086480165030402010500', 'hex');
// TimeStampReq { version 1, messageImprint { sha256, digest }, nonce, certReq TRUE }: the digest is all the TSA learns.
export function timestampQuery(digestHex, nonce) {
  if (!HEX64.test(digestHex)) throw new Error('A timestamp request takes a SHA-256 digest.');
  return der(0x30, der(0x02, Buffer.from([1])), der(0x30, SHA256_ALGORITHM, der(0x04, Buffer.from(digestHex, 'hex'))), der(0x02, nonceInteger(nonce)), der(0x01, Buffer.from([0xff])));
}
// Posts the query and checks the reply: granted, trusted by the key set's TSA roots, over this digest, with this nonce.
export async function requestTimestamp(digestHex, { url, authorities, fetch = globalThis.fetch, timeoutMs = 30000 }) {
  const nonce = randomBytes(8), query = timestampQuery(digestHex, nonce);
  // No redirects: the digest goes to the TSA the key set names and nowhere else.
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/timestamp-query' }, body: query, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`The TSA at ${url} answered HTTP ${response.status}.`);
  const reply = Buffer.from(await response.arrayBuffer());
  if (reply.length > COUNTERSIGN_LIMITS.timestampBytes) throw new Error('The TSA reply is larger than 64 KiB.');
  const stamp = verifyTimestamp(reply, { digest: digestHex, authorities });
  if (stamp.nonce !== nonceInteger(nonce).toString('hex')) throw new Error('The TSA reply does not echo this request\'s nonce.');
  return reply;
}

// Countersigns one envelope end to end: the request, the service, then verification against the key set before anything is
// returned. `timestamp` defaults to the key set's first TSA (or the one at `tsaUrl`, which must be in the set).
export async function countersignEnvelope(envelope, { privateKey, keyset, licenceId, release, tsaUrl, now, timestamp }) {
  const trusted = readKeyset(keyset);
  const authority = tsaUrl === undefined ? trusted.authorities[0] : trusted.authorities.find(a => a.url === tsaUrl);
  if (!authority && !timestamp) throw new Error('The TSA must be one the key set names.');
  const request = countersignRequest(envelope, { licenceId, release });
  const body = JSON.stringify(request);
  const result = await countersignService(body, { privateKey, now, timestamp: timestamp ?? (digest => requestTimestamp(digest, { url: authority.url, authorities: trusted.authorities })) });
  const check = verifyCountersignature({ envelope, countersignature: result.envelope, timestamp: result.timestamp, keyset });
  if (!check.verified) throw new Error(`Countersignature self-check failed (${check.verdict}: ${check.detail}); nothing was written.`);
  return { ...result, sent: body, check };
}
