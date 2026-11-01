// Sign exported evidence and verify it (scopehaven-attest/1). Local operator only.
//   node integrations/attest/cli.mjs keygen --dir ABSOLUTE_PRIVATE_DIR
//   node integrations/attest/cli.mjs sign --key ABSOLUTE_PRIVATE_KEY --out ABSOLUTE_NEW_FILE FILE...
//   node integrations/attest/cli.mjs verify --key ABSOLUTE_PUBLIC_KEY --envelope FILE (--dir DIR | FILE...)
//       [--scopehaven-keys KEYS.json --countersignature NAME.countersign.dsse.json --timestamp NAME.countersign.tsr]
//   node integrations/attest/cli.mjs countersign --envelope ABSOLUTE_ENVELOPE --key ABSOLUTE_SCOPEHAVEN_KEY --licence-id ID
//       [--scopehaven-keys KEYS.json] [--tsa-url URL]
// countersign is ScopeHaven's step, run with ScopeHaven's key (never the operator's): it sends only hashes of the envelope
// (see countersign.mjs), and writes NAME.countersign.dsse.json and NAME.countersign.tsr beside NAME.dsse.json.
// keygen and sign write only new files (never overwrite) into a private directory
// (mode 0700, owned, not a symlink); the private key is written 0600 and never printed.
// Exit codes: 0 done or verified, 1 rejected, 2 usage or file error,
// 3 a negative control was accepted, so this verifier must not be relied on.
import { constants } from 'node:fs';
import { link, lstat, open, readFile, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { generateSigningKey, signFiles } from './sign.mjs';
import { LIMITS, subjectNames, verifyEnvelope } from './verify.mjs';
import { COUNTERSIGN_LIMITS, combined, verifyCountersignature } from './verify-countersign.mjs';
import { countersignEnvelope } from './countersign.mjs';

export const KEY_FILE = 'scopehaven-signing-key.pem';
export const PUBLIC_KEY_FILE = 'scopehaven-signing-key.pub.pem';
// ScopeHaven's published key set, as committed (the same bytes as site/.well-known/scopehaven-keys.json).
export const KEYSET_FILE = fileURLToPath(new URL('./scopehaven-keys.json', import.meta.url));
export const countersignNames = envelope => { const base = envelope.replace(/\.dsse\.json$/, ''); return { countersignature: `${base}.countersign.dsse.json`, timestamp: `${base}.countersign.tsr` }; };
const USAGE = 'Usage: cli.mjs keygen --dir DIR | sign --key PRIVATE_KEY --out NEW_FILE FILE... | verify --key PUBLIC_KEY --envelope FILE (--dir DIR | FILE...) '
  + '[--scopehaven-keys KEYS.json --countersignature FILE --timestamp FILE] | countersign --envelope ENVELOPE --key SCOPEHAVEN_KEY --licence-id ID [--scopehaven-keys KEYS.json] [--tsa-url URL]. '
  + 'Paths for keygen, sign and countersign are absolute; output directories must be mode 0700 and yours.';

const absolute = path => { if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('Paths must be absolute.'); return path; };
async function privateDirectory(path) {
  const stat = await lstat(absolute(path));
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new Error('The directory must be private (mode 0700), owned by you and not a symlink.');
}
// Non-blocking open, so a FIFO is refused instead of waited on; never follows a symlink.
async function readFileSafely(path, limit, { secret = false } = {}) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`${basename(path)} must be a regular file of at most ${limit} bytes.`);
    if (secret && (stat.uid !== process.getuid() || (stat.mode & 0o077))) throw new Error('The private key must be yours and readable only by you (mode 0600).');
    const content = await handle.readFile();
    if (content.length > limit) throw new Error(`${basename(path)} grew past ${limit} bytes while being read.`);
    return { content, inode: `${stat.dev}:${stat.ino}` };
  } finally { await handle.close(); }
}
const readBounded = async (path, limit, options) => (await readFileSafely(path, limit, options)).content;
async function writeNew(path, content, mode) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { await handle.writeFile(content); await handle.sync(); }
  catch (error) { await handle.close(); await unlink(path).catch(() => {}); throw error; }
  await handle.close();
}
function parse(args, flags) {
  const options = {}, files = [];
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith('--')) { files.push(args[i]); continue; }
    const key = flags[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || value === undefined || value.startsWith('--')) throw new Error(USAGE);
    options[key] = value; i++;
  }
  return { options, files };
}

async function keygen(args) {
  const { options, files } = parse(args, { '--dir': 'dir' });
  if (!options.dir || files.length) throw new Error(USAGE);
  await privateDirectory(options.dir);
  const key = generateSigningKey(), privatePath = join(options.dir, KEY_FILE), publicPath = join(options.dir, PUBLIC_KEY_FILE);
  await writeNew(privatePath, key.privatePem, 0o600);
  try { await writeNew(publicPath, key.publicPem, 0o644); }
  catch (error) { await unlink(privatePath).catch(() => {}); throw error; }
  return { code: 0, output: { created: true, keyid: key.keyid, privateKey: privatePath, publicKey: publicPath,
    note: 'Keep the private key on this machine. Give auditors the public key and confirm its keyid with them over a separate channel.' } };
}

async function signCommand(args) {
  const { options, files } = parse(args, { '--key': 'key', '--out': 'out' });
  if (!options.key || !options.out || !files.length) throw new Error(USAGE);
  const out = absolute(options.out); await privateDirectory(dirname(out));
  const key = await readFileSafely(absolute(options.key), 16384, { secret: true }), inputs = [];
  for (const path of files) {
    const { content, inode } = await readFileSafely(absolute(path), LIMITS.subjectBytes);
    if (inode === key.inode || content.includes(key.content.toString('utf8').trim())) throw new Error('The private key file, or a copy of it, cannot be one of the signed files.');
    inputs.push({ name: basename(path), content });
  }
  const privateKey = key.content.toString('utf8');
  const { version } = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const { envelope, check } = signFiles(inputs, { privateKey, version });
  const temporary = join(dirname(out), `.${randomUUID()}.attest.tmp`);
  try { await writeNew(temporary, envelope, 0o644); await link(temporary, out); } // Exclusive publication; never overwrite.
  finally { await unlink(temporary).catch(() => {}); }
  return { code: 0, output: { saved: true, envelope: out, keyid: check.keyid, subjects: check.subjects, runs: check.runs.length, selfChecks: check.selfChecks } };
}

// A countersignature or token file; a missing one is reported as rejected (countersign-missing), not a file error.
const readOptional = (path, limit) => readBounded(resolve(path), limit).catch(error => { if (error.code === 'ENOENT') return undefined; throw error; });

async function verifyCommand(args) {
  const { options, files } = parse(args, { '--key': 'key', '--envelope': 'envelope', '--dir': 'dir', '--scopehaven-keys': 'keyset', '--countersignature': 'countersignature', '--timestamp': 'timestamp' });
  if (!options.key || !options.envelope || (options.dir ? files.length : !files.length)) throw new Error(USAGE);
  // The countersignature is checked only with all three: ScopeHaven's published key set and both files.
  const countersigned = ['keyset', 'countersignature', 'timestamp'].filter(flag => options[flag] !== undefined).length;
  if (countersigned && countersigned !== 3) throw new Error(USAGE);
  const publicKey = (await readBounded(resolve(options.key), 16384)).toString('utf8');
  // One byte past the limit, so an oversized envelope is reported as rejected (envelope-size).
  const envelope = await readBounded(resolve(options.envelope), LIMITS.envelopeBytes + 1);
  const inputs = new Map();
  if (options.dir) {
    // Only names that pass the subject-name rule are read, and only from this directory.
    for (const name of subjectNames(envelope)) {
      try { inputs.set(name, await readBounded(join(resolve(options.dir), name), LIMITS.subjectBytes)); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  } else for (const path of files) {
    const name = basename(path);
    if (inputs.has(name)) throw new Error(`Two files are named ${name}.`);
    inputs.set(name, await readBounded(resolve(path), LIMITS.subjectBytes));
  }
  let result = verifyEnvelope({ envelope, publicKey, files: inputs });
  if (countersigned) {
    const keyset = await readBounded(resolve(options.keyset), COUNTERSIGN_LIMITS.keysetBytes);
    const countersignature = await readOptional(options.countersignature, COUNTERSIGN_LIMITS.envelopeBytes + 1);
    const timestamp = await readOptional(options.timestamp, COUNTERSIGN_LIMITS.timestampBytes + 1);
    result = combined(result, result.verified ? verifyCountersignature({ envelope, countersignature, timestamp, keyset }) : null);
  }
  return { code: { verified: 0, rejected: 1 }[result.verdict] ?? 3, output: result };
}

// ScopeHaven's countersigning step. Like the hosted design, it never reads the operator's files or key: it countersigns the
// hashes this envelope names, and a verifier checks the first signature itself before the countersignature counts.
async function countersignCommand(args) {
  const { options, files } = parse(args, { '--envelope': 'envelope', '--key': 'key', '--licence-id': 'licenceId', '--scopehaven-keys': 'keyset', '--tsa-url': 'tsaUrl' });
  if (!options.envelope || !options.key || !options.licenceId || files.length) throw new Error(USAGE);
  const envelopePath = absolute(options.envelope), out = countersignNames(envelopePath);
  if (out.countersignature === envelopePath) throw new Error('The envelope must be named NAME.dsse.json.');
  await privateDirectory(dirname(envelopePath));
  const key = await readFileSafely(absolute(options.key), 16384, { secret: true });
  const envelope = await readBounded(envelopePath, LIMITS.envelopeBytes);
  const keyset = await readBounded(options.keyset === undefined ? KEYSET_FILE : absolute(options.keyset), COUNTERSIGN_LIMITS.keysetBytes);
  const { version } = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const result = await countersignEnvelope(envelope, { privateKey: key.content.toString('utf8'), keyset, licenceId: options.licenceId, release: version, tsaUrl: options.tsaUrl });
  const written = [];
  try {
    for (const [path, content] of [[out.countersignature, result.envelope], [out.timestamp, result.timestamp]]) {
      const temporary = join(dirname(path), `.${randomUUID()}.attest.tmp`);
      try { await writeNew(temporary, content, 0o644); await link(temporary, path); written.push(path); } // Exclusive publication; never overwrite.
      finally { await unlink(temporary).catch(() => {}); }
    }
  } catch (error) { for (const path of written) await unlink(path).catch(() => {}); throw error; }
  const { check } = result;
  return { code: 0, output: { saved: true, countersignature: out.countersignature, timestamp: out.timestamp, keyid: check.keyid, keyStatus: check.keyStatus,
    firstSignerKeyid: check.firstSignerKeyid, tsa: check.timestamp.tsa, genTime: check.timestamp.genTime, sent: JSON.parse(result.sent), selfChecks: check.selfChecks.length,
    note: 'Only the request in "sent" left this machine for the countersigner, and only the SHA-256 of the countersignature went to the TSA.' } };
}

export async function main(argv) {
  const [command, ...args] = argv;
  try {
    if (command === 'keygen') return await keygen(args);
    if (command === 'sign') return await signCommand(args);
    if (command === 'verify') return await verifyCommand(args);
    if (command === 'countersign') return await countersignCommand(args);
    throw new Error(USAGE);
  } catch (error) { return { code: 2, output: { error: error.message } }; }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const { code, output } = await main(process.argv.slice(2));
  console.log(JSON.stringify(output, null, 2));
  process.exitCode = code;
}
