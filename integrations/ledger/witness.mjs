// Scopehaven evidence ledger: a local witness (C2SP tlog-witness semantics, cosignature/v1 output).
// A witness is a party other than the log operator. It keeps, per log, the last checkpoint it
// cosigned; it countersigns a new checkpoint only if the operator's key signed it and a consistency
// proof shows it extends what the witness already saw. Cosigning the same size with a different root,
// or any shrink, is refused, so an operator who shows two histories cannot get both witnessed.
//
// This module runs where the witness runs, with the witness's own key. It imports the reader's checks
// from verify.mjs and nothing from ledger.mjs (the operator's writer). It sends nothing anywhere: a
// request comes in as data and a cosignature line goes back.
//
//   node witness.mjs keygen --name NAME --out DIR          writes DIR/witness.key (0600) and DIR/witness.vkey
//   node witness.mjs add-log --state DIR --ledger-key PUB --log LOG_ID
//   node witness.mjs add-checkpoint --state DIR --name NAME --key DIR/witness.key --request FILE
// A request is the JSON `ledger cli.mjs witness-request` writes: { checkpoint, oldSize, proof }.
// add-checkpoint answers like tlog-witness: 200 with a cosignature, 400 malformed, 403 not signed by the
// log key, 404 unknown log, 409 the old size is not the size last cosigned (body says that size),
// 422 not a consistent extension.
import { constants } from 'node:fs';
import { open, rename, unlink, writeFile, readFile, lstat, mkdir } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { COSIGNATURE_ORIGIN, checkpointNote, cosignedMessage, cosignerName, readCheckpoint, verifyConsistencyPath, witnessKeyId, LIMITS } from './verify.mjs';
import { Rejected, keyIdOf, trustedKey } from '../attest/verify.mjs';

export const WITNESS_STATE_VERSION = 'scopehaven-witness-state/1';
const NAME_RULE = 'A witness name is a non-empty UTF-8 string of at most 255 bytes without spaces, "+" or control characters.', HEX64 = /^[0-9a-f]{64}$/, LOG_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const rawPublic = key => Buffer.from((key?.type === 'public' ? key : createPublicKey(key)).export({ format: 'jwk' }).x, 'base64url');

// A witness key: Ed25519, used for nothing else (signed-note: one key, one name, one signature type).
export function vkeyOf(name, publicKey) {
  if (!cosignerName(name)) throw new Error(NAME_RULE);
  const raw = rawPublic(publicKey);
  return `${name}+${witnessKeyId(name, raw)}+${Buffer.concat([Buffer.from([4]), raw]).toString('base64')}`;
}
export function generateWitnessKey(name) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { name, privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }), vkey: vkeyOf(name, publicKey) };
}

// The signed-note signature line: "— <name> base64(key id || 8-byte big-endian time || signature)".
// It checks its own inputs, so a direct call cannot sign under a name or tree the verifiers refuse.
export function cosign({ name, privateKey, origin, treeSize, rootHash, time }) {
  if (!cosignerName(name)) throw new Error(NAME_RULE);
  if (typeof origin !== 'string' || !/^scopehaven-ledger\/[^\n]+$/.test(origin) || !Number.isSafeInteger(treeSize) || treeSize < 1 || typeof rootHash !== 'string' || !HEX64.test(rootHash))
    throw new Error('cosign takes a ledger origin, a tree size of at least 1 and a 64-hex root.');
  const key = createPrivateKey(privateKey);
  if (!Number.isSafeInteger(time) || time < 0) throw new Error('time is whole seconds.');
  const signature = sign(null, cosignedMessage(String(time), checkpointNote(origin, treeSize, rootHash)), key);
  const stamp = Buffer.alloc(8); stamp.writeBigUInt64BE(BigInt(time));
  return `— ${name} ${Buffer.concat([Buffer.from(witnessKeyId(name, rawPublic(key)), 'hex'), stamp, signature]).toString('base64')}`;
}

// ---- State: one file, replaced whole under a lock, so the check and the update are one step ----
const statePath = dir => join(dir, 'witness.json');
async function privateDirectory(dir) {
  const stat = await lstat(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new Error(`${dir} must be a private directory (mode 0700), owned by you and not a symlink.`);
}
async function syncDirectory(dir) { const h = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); try { await h.sync(); } finally { await h.close(); } }
async function readState(dir) {
  let text;
  try { const h = await open(statePath(dir), constants.O_RDONLY | constants.O_NOFOLLOW); try { text = (await h.readFile()).toString('utf8'); } finally { await h.close(); } }
  catch (error) { if (error.code === 'ENOENT') return { _type: WITNESS_STATE_VERSION, logs: {} }; throw error; }
  const state = JSON.parse(text);
  if (state?._type !== WITNESS_STATE_VERSION || typeof state.logs !== 'object' || state.logs === null) throw new Error('witness.json is not a witness state file.');
  return state;
}
async function writeState(dir, state) {
  const temp = join(dir, `.witness.json.${randomUUID()}.tmp`);
  const h = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await h.writeFile(`${JSON.stringify(state)}\n`); await h.sync(); } finally { await h.close(); }
  await rename(temp, statePath(dir));
  await syncDirectory(dir);
}
async function withLock(dir, work) {
  const lock = join(dir, '.lock'), token = `${process.pid} ${randomUUID()}\n`;
  let h;
  try { h = await open(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') throw new Error(`${lock} exists: another witness run is active, or one stopped early.`); throw error; }
  try { await h.writeFile(token); } finally { await h.close(); }
  try { return await work(); }
  finally { const held = await readFile(lock, 'utf8').catch(() => null); if (held === token) await unlink(lock).catch(() => {}); }
}

// Trust a log: its origin and the operator's public key. A new log starts at size 0.
export async function addLog(dir, { log, ledgerKey }) {
  await privateDirectory(dir);
  if (!LOG_ID.test(log)) throw new Error('log is the ledger.json log id.');
  trustedKey(ledgerKey);
  return withLock(dir, async () => {
    const state = await readState(dir), origin = COSIGNATURE_ORIGIN(log);
    if (state.logs[origin]) throw new Error(`${origin} is already known to this witness.`);
    state.logs[origin] = { ledgerKey, size: 0, rootHash: null };
    await writeState(dir, state);
    return { origin, size: 0 };
  });
}

const answer = (status, body) => ({ status, ...body });
// tlog-witness add-checkpoint, checks in the spec's order. Returns { status, ... }; only 200 carries a
// cosignature, and only 200 changes the state.
export async function addCheckpoint(dir, { name, privateKey, request, now = new Date() }) {
  await privateDirectory(dir);
  if (!cosignerName(name)) throw new Error(NAME_RULE);
  return withLock(dir, async () => {
    const state = await readState(dir);
    const { checkpoint, oldSize, proof } = request ?? {};
    let log;
    try { log = JSON.parse(Buffer.from(JSON.parse(checkpoint).payload, 'base64').toString('utf8')).log; } catch { return answer(400, { error: 'not a ledger checkpoint' }); }
    const origin = COSIGNATURE_ORIGIN(String(log)), known = Object.hasOwn(state.logs, origin) ? state.logs[origin] : null;
    if (!known) return answer(404, { error: `unknown log ${origin}` });
    let point;
    try { const key = trustedKey(known.ledgerKey); point = readCheckpoint(checkpoint, key, keyIdOf(key), log); }
    catch (error) {
      if (!(error instanceof Rejected)) throw error;
      return ['keyid-mismatch', 'checkpoint-signature'].includes(error.reason) ? answer(403, { error: 'not signed by the log key this witness trusts' }) : answer(400, { error: `checkpoint: ${error.reason}` });
    }
    if (!Number.isSafeInteger(oldSize) || oldSize < 0 || oldSize > point.treeSize || !Array.isArray(proof) || proof.length > LIMITS.proofLength
      || !proof.every(h => typeof h === 'string' && HEX64.test(h))) return answer(400, { error: 'old size or proof malformed' });
    if (oldSize !== known.size) return answer(409, { error: 'old size is not the size this witness last cosigned', size: known.size });
    // tlog-witness: a proof that does not verify is 422, including a non-empty one from old size 0 and,
    // as RFC 9162 has no proof between equal sizes, a non-empty one at the same size.
    if ((oldSize === 0 || oldSize === point.treeSize) && proof.length) return answer(422, { error: 'the consistency proof does not verify' });
    if (oldSize > 0) {
      const consistent = oldSize === point.treeSize ? point.rootHash === known.rootHash
        : verifyConsistencyPath(oldSize, point.treeSize, proof.map(h => Buffer.from(h, 'hex')), Buffer.from(known.rootHash, 'hex'), Buffer.from(point.rootHash, 'hex'));
      if (!consistent) return answer(422, { error: 'not a consistent extension of what this witness cosigned' });
    }
    state.logs[origin] = { ...known, size: point.treeSize, rootHash: point.rootHash };
    await writeState(dir, state);
    const time = Math.floor(now.getTime() / 1000);
    return answer(200, { cosignature: { treeSize: point.treeSize, rootHash: point.rootHash, cosignature: cosign({ name, privateKey, origin, treeSize: point.treeSize, rootHash: point.rootHash, time }) } });
  });
}

// ---- CLI ----
const USAGE = 'Usage: witness.mjs keygen --name NAME --out DIR | add-log --state DIR --ledger-key PUB --log LOG_ID | add-checkpoint --state DIR --name NAME --key FILE --request FILE';
const absolute = path => { if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('Paths must be absolute.'); return path; };
function parse(args, flags) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = flags[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || value === undefined) throw new Error(USAGE);
    options[key] = value;
  }
  return options;
}
async function readSmall(path, limit, { secret = false } = {}) {
  const h = await open(absolute(path), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await h.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`${path} must be a regular file of at most ${limit} bytes.`);
    if (secret && (stat.uid !== process.getuid() || (stat.mode & 0o077))) throw new Error('The witness key must be yours and readable only by you (mode 0600).');
    return (await h.readFile()).toString('utf8');
  } finally { await h.close(); }
}
const commands = {
  async keygen(args) {
    const o = parse(args, { '--name': 'name', '--out': 'out' });
    if (!o.name || !o.out) throw new Error(USAGE);
    await mkdir(absolute(o.out), { recursive: true, mode: 0o700 }); await privateDirectory(o.out);
    const key = generateWitnessKey(o.name);
    await writeFile(join(o.out, 'witness.key'), key.privatePem, { mode: 0o600, flag: 'wx' });
    await writeFile(join(o.out, 'witness.vkey'), `${key.vkey}\n`, { flag: 'wx' });
    return { code: 0, output: { name: o.name, vkey: key.vkey } };
  },
  async 'add-log'(args) {
    const o = parse(args, { '--state': 'state', '--ledger-key': 'ledgerKey', '--log': 'log' });
    if (!o.state || !o.ledgerKey || !o.log) throw new Error(USAGE);
    return { code: 0, output: await addLog(absolute(o.state), { log: o.log, ledgerKey: await readSmall(o.ledgerKey, 16384) }) };
  },
  async 'add-checkpoint'(args) {
    const o = parse(args, { '--state': 'state', '--name': 'name', '--key': 'key', '--request': 'request' });
    if (!o.state || !o.name || !o.key || !o.request) throw new Error(USAGE);
    let request;
    try { request = JSON.parse(await readSmall(o.request, 1024 * 1024)); } catch (error) { if (error instanceof SyntaxError) return { code: 1, output: { status: 400, error: 'request is not JSON' } }; throw error; }
    const result = await addCheckpoint(absolute(o.state), { name: o.name, privateKey: await readSmall(o.key, 16384, { secret: true }), request });
    return { code: result.status === 200 ? 0 : 1, output: result };
  },
};
export async function main(argv) {
  const [command, ...args] = argv;
  try {
    if (!Object.hasOwn(commands, command)) throw new Error(USAGE);
    return await commands[command](args);
  } catch (error) { return { code: 2, output: { error: error.message } }; }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const { code, output } = await main(process.argv.slice(2));
  console.log(JSON.stringify(output, null, 2));
  process.exitCode = code;
}
