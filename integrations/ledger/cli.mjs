// Evidence ledger commands (scopehaven-ledger/1). Local operator only.
//   init       --ledger DIR                                   (DIR exists, mode 0700)
//   append     --ledger DIR --key PRIVATE --evidence-key PUB --envelope FILE (--dir DIR | FILE...) [--anchors FILE]
//              signs a checkpoint over the new entry before writing, kept in pending.json until it is appended;
//              prints the entry's lineSha256
//              anchors FILE: {"<run file name>": [{ "source", "count", "head", "declaredCustody"? }]} (EVID-SUBJECT anchorOf output)
//   checkpoint --ledger DIR --key PRIVATE [--evidence-key PUB]   recovery only: finishes the append in pending.json
//              exactly as signed. It signs nothing new, and refuses any line that append did not write.
//   prove      --ledger DIR --index N [--size M]          inclusion proof (M defaults to the latest checkpoint)
//   prove      --ledger DIR --from M --to N               consistency proof
//   verify     --ledger DIR --key PUB [--evidence-key PUB] [--run-files DIR] [--witnesses FILE [--quorum K]]
//              run files compare recorded verdicts; witnesses FILE: one cosignature/v1 vkey per line (# comments),
//              quorum K of them must cosign a checkpoint for it to count as witnessed (default: all)
//   history    --ledger DIR --key PUB [--evidence-key PUB]  verifies first, then prints verdict changes
//   witness-request --ledger DIR [--old-size N]   what a witness (witness.mjs) needs to cosign the latest checkpoint
//   add-cosignature --ledger DIR --cosignature FILE   stores a witness's cosignature record in cosignatures.jsonl
// Keys are the Ed25519 PEM files `integrations/attest/cli.mjs keygen` writes.
// Exit codes: 0 done or verified, 1 rejected, 2 usage or file error, 3 a negative control was accepted.
import { constants } from 'node:fs';
import { open, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { addCosignature, appendEnvelope, checkpointLedger, consistencyProof, inclusionProof, initLedger, readLedgerFiles, witnessRequest } from './ledger.mjs';
import { verifyLedger } from './verify.mjs';
import { permissionHistory } from './history.mjs';
import { subjectNames } from '../attest/verify.mjs';

const USAGE = 'Usage: cli.mjs init|append|checkpoint|prove|verify|history|witness-request|add-cosignature --ledger DIR ... (see the header of integrations/ledger/cli.mjs)';
async function readFileSafely(path, limit, { secret = false } = {}) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`${basename(path)} must be a regular file of at most ${limit} bytes.`);
    if (secret && (stat.uid !== process.getuid() || (stat.mode & 0o077))) throw new Error('The private key must be yours and readable only by you (mode 0600).');
    return await handle.readFile();
  } finally { await handle.close(); }
}
function parse(args, flags) {
  const options = {}, files = [];
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith('--')) { files.push(args[i]); continue; }
    const key = flags[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || value === undefined || value.startsWith('--')) throw new Error(USAGE);
    options[key] = value; i++;
  }
  if (!options.ledger || !isAbsolute(options.ledger)) throw new Error('--ledger must be an absolute path.');
  return { options, files };
}
const integer = value => { const n = Number(value); if (!Number.isSafeInteger(n)) throw new Error(USAGE); return n; };
const pem = path => readFileSafely(resolve(path), 16384).then(b => b.toString('utf8'));
// Every command takes absolute paths only.
const absolute = path => { if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('Paths must be absolute.'); return path; };
const linesOf = bytes => { const text = bytes.toString('utf8'); return text ? text.slice(0, -1).split('\n') : []; };

async function runFilesIn(dir) {
  const files = new Map();
  for (const entry of await readdir(resolve(dir), { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const bytes = await readFileSafely(join(resolve(dir), entry.name), 8 * 1024 * 1024);
    files.set(createHash('sha256').update(bytes).digest('hex'), bytes);
  }
  return files;
}
// verify and history take absolute paths too, like every other command.
async function verified(options) {
  const files = await readLedgerFiles(options.ledger);
  if (options.quorum !== undefined && (!options.witnesses || !/^[1-9][0-9]{0,2}$/.test(options.quorum))) throw new Error('--quorum is a whole number, given with --witnesses.');
  return verifyLedger({ ...files, ledgerKey: await pem(absolute(options.key)), evidenceKey: options.evidenceKey ? await pem(absolute(options.evidenceKey)) : undefined,
    runFiles: options.runFiles ? await runFilesIn(absolute(options.runFiles)) : undefined,
    witnesses: options.witnesses ? witnessKeysIn(await readFileSafely(absolute(options.witnesses), 65536)) : undefined,
    quorum: options.quorum === undefined ? undefined : Number(options.quorum) });
}
// One vkey per line (the same in verify_ledger.py): spaces and tabs around a line are dropped, blank lines
// and comments ("#" alone, or "#" then a space or tab) are skipped, and every other line is a vkey. A vkey
// holds no space, so a witness name may start with "#"; a key disabled as "#vkey" fails loudly instead.
const witnessKeysIn = bytes => bytes.toString('utf8').split('\n').map(line => line.replace(/\r$/, '').replace(/^[ \t]+|[ \t]+$/g, ''))
  .filter(line => line && line !== '#' && !/^#[ \t]/.test(line));
const exit = result => ({ verified: 0, rejected: 1 }[result.verdict] ?? 3);

const commands = {
  async init(args) {
    const { options } = parse(args, { '--ledger': 'ledger' });
    return { code: 0, output: { created: true, ...(await initLedger(options.ledger)) } };
  },
  async append(args) {
    const { options, files } = parse(args, { '--ledger': 'ledger', '--key': 'key', '--evidence-key': 'evidenceKey', '--envelope': 'envelope', '--dir': 'dir', '--anchors': 'anchors' });
    if (!options.key || !options.evidenceKey || !options.envelope || (options.dir ? files.length : !files.length)) throw new Error(USAGE);
    const privateKey = (await readFileSafely(absolute(options.key), 16384, { secret: true })).toString('utf8');
    const envelope = await readFileSafely(absolute(options.envelope), 2 * 1024 * 1024), inputs = new Map();
    if (options.dir) for (const name of subjectNames(envelope)) inputs.set(name, await readFileSafely(join(absolute(options.dir), name), 8 * 1024 * 1024));
    else for (const path of files) inputs.set(basename(path), await readFileSafely(absolute(path), 8 * 1024 * 1024));
    const anchors = options.anchors ? new Map(Object.entries(JSON.parse((await readFileSafely(absolute(options.anchors), 1024 * 1024)).toString('utf8')))) : undefined;
    const { line, checkpoint, ...added } = await appendEnvelope(options.ledger, { envelope, files: inputs, evidenceKey: await pem(absolute(options.evidenceKey)), privateKey, anchors });
    return { code: 0, output: { appended: true, witness: 'none', ...added } };
  },
  async checkpoint(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--key': 'key', '--evidence-key': 'evidenceKey' });
    if (!options.key) throw new Error(USAGE);
    const privateKey = (await readFileSafely(absolute(options.key), 16384, { secret: true })).toString('utf8');
    const evidenceKey = options.evidenceKey ? await pem(absolute(options.evidenceKey)) : undefined;
    // The CLI's append always signs, so the only tail it can account for is the one in pending.json.
    const { line, ...finished } = await checkpointLedger(options.ledger, { privateKey, evidenceKey });
    return { code: 0, output: { witness: 'none', ...finished } };
  },
  async prove(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--index': 'index', '--size': 'size', '--from': 'from', '--to': 'to' });
    const { metadata, entries, checkpoints } = await readLedgerFiles(options.ledger);
    const log = JSON.parse(metadata.toString('utf8')).log, lines = linesOf(entries), points = linesOf(checkpoints);
    if (options.index !== undefined) {
      const latest = points.length ? JSON.parse(Buffer.from(JSON.parse(points.at(-1)).payload, 'base64').toString('utf8')).treeSize : lines.length;
      const index = integer(options.index), treeSize = options.size === undefined ? latest : integer(options.size);
      return { code: 0, output: { entry: lines[index] ?? null, proof: inclusionProof({ log, lines, index, treeSize }) } };
    }
    if (options.from === undefined || options.to === undefined) throw new Error(USAGE);
    return { code: 0, output: consistencyProof({ log, lines, from: integer(options.from), to: integer(options.to) }) };
  },
  async verify(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--key': 'key', '--evidence-key': 'evidenceKey', '--run-files': 'runFiles', '--witnesses': 'witnesses', '--quorum': 'quorum' });
    if (!options.key) throw new Error(USAGE);
    const { entries, ...result } = await verified(options);
    return { code: exit(result), output: result };
  },
  async 'witness-request'(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--old-size': 'oldSize' });
    return { code: 0, output: await witnessRequest(options.ledger, { oldSize: options.oldSize === undefined ? 0 : integer(options.oldSize) }) };
  },
  async 'add-cosignature'(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--cosignature': 'cosignature' });
    if (!options.cosignature) throw new Error(USAGE);
    let record;
    try { record = JSON.parse((await readFileSafely(absolute(options.cosignature), 65536)).toString('utf8')); } catch (error) { if (error instanceof SyntaxError) throw new Error('The cosignature file is not JSON.'); throw error; }
    return { code: 0, output: await addCosignature(options.ledger, record?.cosignature && typeof record.cosignature === 'object' ? record.cosignature : record) };
  },
  async history(args) {
    const { options } = parse(args, { '--ledger': 'ledger', '--key': 'key', '--evidence-key': 'evidenceKey' });
    if (!options.key) throw new Error(USAGE);
    const result = await verified(options);
    if (result.verdict !== 'verified') { const { entries, ...rest } = result; return { code: exit(result), output: rest }; }
    return { code: 0, output: permissionHistory(result) };
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
