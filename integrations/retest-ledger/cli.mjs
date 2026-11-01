// Retest history CLI. Every path is absolute.
//   build   --ledger DIR --key PUB [--evidence-key PUB] --run-files DIR --declarations FILE [--require-reasons]
//           verifies the ledger with every run's signed file, then prints the history
//   export  (build's options) --out NEW_DIR [--signing-key-dir DIR]
//           writes retest-history.json, its DSSE envelope and the signer's public key into a new private folder
//   verify  (build's options) --history DIR
//           checks the folder's envelope against its public key, then rebuilds the history and compares the bytes
// Exit codes: 0 done (verify: reproduced), 1 refused or not reproduced, 2 usage or file error.
// --require-reasons refuses a history in which a finding is open without a declared reason.
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, rename, rm, rmdir } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { assertRuntime } from '../../src/runtime.mjs';
import { loadSigningKey, publish, defaultSigningKeyDir, signerVersion } from '../../src/export-cli.mjs';
import { readLedgerFiles } from '../ledger/ledger.mjs';
import { verifyLedger } from '../ledger/verify.mjs';
import { signFiles } from '../attest/sign.mjs';
import { savedRun, verifyEnvelope, subjectNames } from '../attest/verify.mjs';
import { PUBLIC_KEY_FILE } from '../attest/cli.mjs';
import { readDeclarations, retestHistory } from './history.mjs';

export const HISTORY_FILE = 'retest-history.json';
export const HISTORY_ENVELOPE = `${HISTORY_FILE}.dsse.json`;
const USAGE = 'Usage: cli.mjs build|export|verify --ledger DIR --key PUB [--evidence-key PUB] --run-files DIR --declarations FILE [--require-reasons] [--out NEW_DIR [--signing-key-dir DIR] | --history DIR] (absolute paths)';
const usage = (detail = USAGE) => Object.assign(new Error(detail), { usage: true });

async function readSafely(path, limit) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw usage(`${path} must be a regular file of at most ${limit} bytes.`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
const absolute = (value, flag) => { if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) throw usage(`${flag} must be an absolute path.`); return value; };
function parse(args) {
  const flags = { '--ledger': 'ledger', '--key': 'key', '--evidence-key': 'evidenceKey', '--run-files': 'runFiles', '--declarations': 'declarations', '--out': 'out', '--signing-key-dir': 'signingKeyDir', '--history': 'history' };
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--require-reasons') { if (options.requireReasons) throw usage(); options.requireReasons = true; continue; }
    const key = flags[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || value === undefined || value.startsWith('--')) throw usage();
    options[key] = absolute(value, args[i]); i++;
  }
  for (const key of ['ledger', 'key', 'runFiles', 'declarations']) if (!options[key]) throw usage();
  return options;
}

// Run exports in a folder: every *.json that attest reads as a native run (its integrity hash recomputed). Envelopes are skipped;
// a payments run is read by the ledger verifier but not by the history, which reads run exports only.
async function runFilesIn(dir) {
  const bytesByDigest = new Map(), runs = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.json') || entry.name.endsWith('.dsse.json')) continue;
    const bytes = await readSafely(join(dir, entry.name), 8 * 1024 * 1024);
    // Every file goes to the ledger verifier, which checks the ones an entry names (payments runs included).
    bytesByDigest.set(createHash('sha256').update(bytes).digest('hex'), bytes);
    let read;
    try { read = savedRun(entry.name, bytes); } catch { continue; }
    if (!read || read.payments) continue;
    runs.push({ core: read.core, coreSha256: read.coreSha256 });
  }
  return { runs, bytesByDigest };
}

export async function buildHistory(options) {
  assertRuntime();
  const pem = async path => (await readSafely(path, 16384)).toString('utf8');
  const ledgerKey = await pem(options.key), evidenceKey = options.evidenceKey ? await pem(options.evidenceKey) : undefined;
  const { runs, bytesByDigest } = await runFilesIn(options.runFiles);
  const verified = verifyLedger({ ...(await readLedgerFiles(options.ledger)), ledgerKey, evidenceKey, runFiles: bytesByDigest });
  if (verified.verdict !== 'verified') return { refused: true, output: { verdict: verified.verdict, reason: verified.reason, detail: verified.detail } };
  let declarations;
  try { declarations = readDeclarations(JSON.parse((await readSafely(options.declarations, 4 * 1024 * 1024)).toString('utf8'))); }
  catch (error) { return { refused: true, output: { verdict: 'refused', reason: error.code ?? 'declarations-unreadable', detail: error.message } }; }
  let history;
  try { history = retestHistory(verified, runs, declarations); }
  catch (error) { if (error.code !== 'retest-history-refused') throw error; return { refused: true, output: { verdict: 'refused', reason: error.code, detail: error.message } }; }
  if (options.requireReasons && history.counts.openWithoutReason) return { refused: true, output: { verdict: 'refused', reason: 'open-without-reason', detail: `${history.counts.openWithoutReason} open finding(s) have no declared reason.`, history } };
  return { refused: false, history, bytes: Buffer.from(`${JSON.stringify(history, null, 2)}\n`) };
}

// A new private folder, built beside --out and renamed into place only when complete and verified.
async function exportHistory(options) {
  const out = options.out, parent = dirname(out);
  if (await lstat(out).then(() => true, e => { if (e.code === 'ENOENT') return false; throw e; })) throw usage('--out already exists.');
  const built = await buildHistory(options);
  if (built.refused) return built;
  const signer = await loadSigningKey(options.signingKeyDir ?? defaultSigningKeyDir());
  const staging = join(parent, `.${randomUUID()}.retest-history.tmp`);
  let claimed = false;
  try {
    await mkdir(staging, { mode: 0o700 }); await chmod(staging, 0o700);
    const { envelope } = signFiles([{ name: HISTORY_FILE, content: built.bytes }], { privateKey: signer.privateKey, version: await signerVersion() });
    const publicPem = createPublicKey(signer.privateKey).export({ type: 'spki', format: 'pem' });
    await publish(join(staging, HISTORY_FILE), built.bytes);
    await publish(join(staging, HISTORY_ENVELOPE), Buffer.from(envelope));
    await publish(join(staging, PUBLIC_KEY_FILE), Buffer.from(publicPem), 0o644);
    const check = verifyEnvelope({ envelope: Buffer.from(envelope), publicKey: publicPem, files: new Map([[HISTORY_FILE, built.bytes]]) });
    if (!check.verified) throw new Error(`The history envelope did not verify (${check.verdict}).`);
    // Claimed only now, exclusively (EEXIST if anything took the name meanwhile), then the staging folder replaces the empty
    // claim in one step; a folder someone filled in between fails ENOTEMPTY and is left as it is.
    await mkdir(out, { mode: 0o700 }).catch(error => { throw error.code === 'EEXIST' ? usage('--out already exists.') : error; });
    claimed = true;
    await rename(staging, out);
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => {});
    if (claimed) await rmdir(out).catch(() => {});
    throw error;
  }
  return { refused: false, output: { saved: true, out, keyid: signer.keyid, counts: built.history.counts, files: [HISTORY_FILE, HISTORY_ENVELOPE, PUBLIC_KEY_FILE],
    verify: `python3 -I integrations/attest/verify_envelope.py --key ${join(out, PUBLIC_KEY_FILE)} --envelope ${join(out, HISTORY_ENVELOPE)} --dir ${out}` } };
}

async function verifyHistory(options) {
  const dir = options.history;
  const [envelope, publicPem, bytes] = await Promise.all([readSafely(join(dir, HISTORY_ENVELOPE), 2 * 1024 * 1024), readSafely(join(dir, PUBLIC_KEY_FILE), 16384), readSafely(join(dir, HISTORY_FILE), 64 * 1024 * 1024)]);
  if (JSON.stringify(subjectNames(envelope)) !== JSON.stringify([HISTORY_FILE])) return { refused: true, output: { verdict: 'rejected', reason: 'envelope-subjects', detail: `The envelope must name only ${HISTORY_FILE}.` } };
  const check = verifyEnvelope({ envelope, publicKey: publicPem.toString('utf8'), files: new Map([[HISTORY_FILE, bytes]]) });
  if (!check.verified) return { refused: true, output: { verdict: 'rejected', reason: check.reason ?? check.verdict, keyid: check.keyid ?? null } };
  const built = await buildHistory(options);
  if (built.refused) return built;
  const reproduced = Buffer.compare(built.bytes, bytes) === 0;
  return { refused: !reproduced, output: { verdict: reproduced ? 'reproduced' : 'not-reproduced', keyid: check.keyid, signature: 'verified', counts: built.history.counts,
    note: 'The signature shows who produced the file; the rebuild shows the file is what this ledger, these run files and these declarations give. Compare the key id with the signer over another channel.' } };
}

export async function main(argv) {
  const [command, ...args] = argv;
  const options = parse(args);
  if (command === 'build') { if (options.out || options.history || options.signingKeyDir) throw usage(); const r = await buildHistory(options); return { code: r.refused ? 1 : 0, output: r.refused ? r.output : r.history }; }
  if (command === 'export') { if (!options.out || options.history) throw usage(); const r = await exportHistory(options); return { code: r.refused ? 1 : 0, output: r.output }; }
  if (command === 'verify') { if (!options.history || options.out || options.signingKeyDir) throw usage(); const r = await verifyHistory(options); return { code: r.refused ? 1 : 0, output: r.output }; }
  throw usage();
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { const { code, output } = await main(process.argv.slice(2)); console.log(JSON.stringify(output, null, 2)); process.exitCode = code; }
  catch (error) { console.error(error.usage ? error.message : `Retest history failed (${error.message}).`); process.exitCode = 2; }
}
