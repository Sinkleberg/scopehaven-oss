#!/usr/bin/env node
// CI mode for the Scopehaven composite action: signed exports, the evidence ledger, pinned pack versions and a baseline read
// from the ledger. Zero dependencies; local files only; nothing is sent anywhere. It uses the existing code read-only:
// integrations/attest (envelope verification), integrations/ledger (its cli.mjs for append and verify, its verifier and readers
// for the baseline) and integrations/packs-v2 (the load's own lock check). It never prints key material: only key ids, hashes,
// run ids, pack names and versions, and reason codes.
//   pack-lock --profile ABS --lock ABS [--out ABS_NEW_FILE]
//       verifies the profile's packs against the lock beside it, as a profile load does; prints the lockId (and, with --out,
//       writes the record of the pinned packs)
//   ledger-baseline --ledger ABS --ledger-key-dir ABS --signing-key-dir ABS --run-files ABS --profile ABS --target ID
//                   --copy ABS_NEW_FILE --out ABS_NEW_FILE
//       verifies the ledger (with the kept run files) and copies the latest signed run of this target and application to
//       --copy; prints that path, or an empty line when the ledger holds no run of this target yet
//   ci-evidence --root ABS --export ABS --run-id ID --signing-key-dir ABS [--comparison true]
//               [--ledger ABS --ledger-key-dir ABS --run-files ABS]
//       verifies every signed export, then (with --ledger) keeps run.json in the run files, appends its envelope with
//       integrations/ledger/cli.mjs append and verifies the ledger with cli.mjs verify; prints GITHUB_OUTPUT lines
//   summary --export ABS [--ci-state S] [--ci-reason R]
//       the job summary's "CI evidence" section, from the records the other commands wrote (nothing when there are none)
// A refusal prints its reason code alone on stdout (the message goes to stderr) and exits 2.
import { constants } from 'node:fs';
import { lstat, open, readdir, unlink } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readLedgerFiles } from '../ledger/ledger.mjs';
import { verifyLedger, isPaymentsRun } from '../ledger/verify.mjs';
import { readSignedStatement } from '../attest/verify.mjs';
import { KEY_FILE, PUBLIC_KEY_FILE } from '../attest/cli.mjs';
import { expandPacks, readProfileFile, usesPacks, LOCK_FILE, LOCK_SCHEMA } from '../packs-v2/expand.mjs';
import { admitDraftedLines } from '../watch-first/lines.mjs';
import { baselineRecord } from './prepare.mjs';

export const PACK_LOCK_SCHEMA = 'scopehaven-action-pack-lock/1';
export const LEDGER_BASELINE_SCHEMA = 'scopehaven-action-ledger-baseline/1';
export const CI_EVIDENCE_SCHEMA = 'scopehaven-action-ci-evidence/1';
// The files the export step signs (their envelopes are NAME.dsse.json beside them), and the ledger's public key name in the artifact.
export const SIGNED_EXPORTS = Object.freeze(['run.json', 'report.html', 'scopehaven.sarif']);
export const LEDGER_PUBLIC_KEY = 'ledger-key.pub.pem';
export { KEY_FILE, PUBLIC_KEY_FILE };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CODE = /^[a-z][a-z0-9-]{1,60}$/;
const TARGET = /^[A-Za-z0-9_-]{1,80}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export class CiRefusal extends Error {
  constructor(code, detail) { super(`${code}: ${detail}`); this.code = code; }
}
const refuse = (code, detail) => { throw new CiRefusal(code, detail); };

/** One regular file of at most `limit` bytes, opened without following a link or blocking on a pipe. */
async function readRegular(path, limit, code) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { refuse(code, `${basename(path)} cannot be opened (${error.code === 'ELOOP' ? 'a symlink' : error.code ?? 'error'})`); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) refuse(code, `${basename(path)} must be a regular file of at most ${limit} bytes`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
/** A new private file (0600, exclusive, never through a link). */
async function writeNew(path, content) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
}
const json = value => `${JSON.stringify(value, null, 2)}\n`;
async function privateDirectory(path, code) {
  let stat;
  try { stat = await lstat(path); } catch { refuse(code, `${basename(path)} does not exist`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) refuse(code, `${basename(path)} must be a directory of mode 0700, owned by you and not a symlink`);
}
const absolute = (value, name) => { if (typeof value !== 'string' || !isAbsolute(value) || value.includes('\n')) refuse('invalid-options', `${name} must be an absolute path`); return value; };

// ---- Pinned pack versions ----

/** The profile's packs checked against scopehaven.lock beside it, by packs-v2's own load check (expandPacks): every referenced
 * pack's files match its manifest, the lock is unedited (its lockId) and pins each reference with the same digests. The lock's
 * bytes are read before and after the check and must not change in between. Writes the record and returns the lockId. */
export async function packLock({ profile, lock, out }) {
  const profileFile = resolve(absolute(profile, '--profile')), lockFile = resolve(absolute(lock, '--lock'));
  if (lockFile !== join(dirname(profileFile), LOCK_FILE)) refuse('pack-lock-not-beside-profile', `pack-lock must be the ${LOCK_FILE} beside the profile, the one a profile load reads`);
  const before = await readRegular(lockFile, 262144, 'pack-lock-invalid');
  let input;
  try { input = admitDraftedLines(await readProfileFile(profileFile)); }
  catch (error) { refuse(CODE.test(error.code ?? '') ? error.code : 'pack-reference-invalid', error.message); }
  if (!usesPacks(input)) refuse('pack-lock-unused', 'the profile references no packs, so a lock pins nothing for this run');
  try { await expandPacks(input, { profileFile }); }
  catch (error) { refuse(CODE.test(error.code ?? '') ? error.code : 'pack-lock-invalid', error.message); }
  const after = await readRegular(lockFile, 262144, 'pack-lock-invalid');
  if (!before.equals(after)) refuse('pack-lock-changed', `${LOCK_FILE} changed while it was being checked`);
  const parsed = JSON.parse(after.toString('utf8'));
  if (parsed?.schema !== LOCK_SCHEMA || typeof parsed.lockId !== 'string' || !HEX64.test(parsed.lockId)) refuse('pack-lock-invalid', `${LOCK_FILE} is not a ${LOCK_SCHEMA} lock`);
  const referenced = input.targets.filter(t => object(t) && Array.isArray(t.packs))
    .flatMap(t => t.packs.map(ref => ({ target: t.id, name: ref.name, version: ref.version, as: ref.as, from: ref.from ?? null })));
  const record = {
    schema: PACK_LOCK_SCHEMA, lockFile: LOCK_FILE, lockSha256: sha256(after), lockId: parsed.lockId,
    meaning: 'The packs this run\'s profile references, verified against its lock by the packs-v2 load check before any request. The digests are checksums, not signatures: they show the pack files did not drift from the lock, not who wrote them.',
    referenced,
    packs: parsed.packs.map(p => ({ name: p.name, version: p.version, from: p.from ?? null, manifest: p.manifest, files: p.files })),
  };
  // Without --out it only checks (the prepare step checks before the authorization check, then again to write the record).
  if (out !== undefined) await writeNew(resolve(absolute(out, '--out')), json(record));
  return parsed.lockId;
}

// ---- The ledger ----

async function runFilesIn(dir) {
  const files = new Map();
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const bytes = await readRegular(join(dir, entry.name), 8 * 1024 * 1024, 'ledger-run-files-invalid');
    files.set(sha256(bytes), bytes);
  }
  return files;
}
async function keyPair(dir, code) {
  await privateDirectory(dir, code);
  for (const name of [KEY_FILE, PUBLIC_KEY_FILE]) await readRegular(join(dir, name), 16384, code);
  return { privatePath: join(dir, KEY_FILE), publicPath: join(dir, PUBLIC_KEY_FILE), publicPem: (await readRegular(join(dir, PUBLIC_KEY_FILE), 16384, code)).toString('utf8') };
}
function profileTarget(bytes, target) {
  let input;
  try { input = JSON.parse(bytes.toString('utf8')); } catch { refuse('invalid-options', 'the profile is not valid JSON'); }
  const found = object(input) && Array.isArray(input.targets) ? input.targets.find(t => object(t) && t.id === target) : null;
  if (!found || typeof found.applicationId !== 'string') refuse('invalid-options', 'the profile names no such target with an applicationId');
  return found;
}

/** The latest signed run of this target and application in a verified ledger, or null. Selection is by target id and application
 * id; the gate then decides whether that run is comparable (suite, policy, evaluator and the rest, as for any baseline-run). */
export async function ledgerBaseline({ ledger, ledgerKeyDir, signingKeyDir, runFiles, profile, target, copy, out }) {
  absolute(ledger, '--ledger'); absolute(runFiles, '--run-files'); absolute(copy, '--copy'); absolute(out, '--out');
  if (!TARGET.test(target ?? '')) refuse('invalid-options', '--target must be a target id');
  const app = profileTarget(await readRegular(absolute(profile, '--profile'), 2 * 1024 * 1024, 'invalid-options'), target).applicationId;
  await privateDirectory(ledger, 'ledger-dir-unsafe');
  await privateDirectory(runFiles, 'ledger-run-files-unsafe');
  const ledgerKey = await keyPair(absolute(ledgerKeyDir, '--ledger-key-dir'), 'ledger-key-unsafe');
  const evidenceKey = await keyPair(absolute(signingKeyDir, '--signing-key-dir'), 'signing-key-unsafe');
  let files;
  try { files = await readLedgerFiles(ledger); } catch (error) { refuse('ledger-unreadable', error.message); }
  const base = { schema: LEDGER_BASELINE_SCHEMA, target, applicationId: app,
    rule: 'The latest run in the verified ledger with this target id and application id. The gate decides whether it is comparable; an incompatible one fails the job (incompatible-baseline).' };
  // A ledger just made with `cli.mjs init` holds no entry and no checkpoint: there is nothing to compare with yet.
  if (!files.entries.length && !files.checkpoints.length) {
    await writeNew(out, json({ ...base, state: 'none', reason: 'ledger-empty', ledger: { size: 0 } }));
    return '';
  }
  const kept = await runFilesIn(runFiles);
  const verified = verifyLedger({ ...files, ledgerKey: ledgerKey.publicPem, evidenceKey: evidenceKey.publicPem, runFiles: kept });
  if (verified.verdict !== 'verified') refuse('ledger-unverified', `the ledger did not verify (${verified.reason})`);
  if (verified.unsignedTail) refuse('ledger-unsigned-tail', 'the ledger has entries no checkpoint covers');
  let chosen = null;
  for (const entry of [...verified.entries].reverse()) {
    const run = [...entry.runs].reverse().find(r => !isPaymentsRun(r) && r.targetId === target && r.applicationId === app);
    if (run) { chosen = { entry, run }; break; }
  }
  const ledgerInfo = { log: verified.log, size: verified.size, rootHash: verified.checkpoints.at(-1).rootHash };
  if (!chosen) {
    await writeNew(out, json({ ...base, state: 'none', reason: 'no-run-for-target', ledger: ledgerInfo }));
    return '';
  }
  // The run file is found by the digest the evidence key signed for it, so the baseline is the signed bytes.
  const envelope = files.envelopes.get(chosen.entry.envelope.sha256);
  let subject;
  try { subject = readSignedStatement(envelope, evidenceKey.publicPem).statement.subject.find(s => s?.name === chosen.run.subject); }
  catch (error) { refuse('ledger-baseline-envelope-invalid', error.message); }
  const digest = subject?.digest?.sha256, bytes = typeof digest === 'string' ? kept.get(digest) : undefined;
  if (!bytes) refuse('ledger-baseline-run-file-missing', `the run file of run ${chosen.run.id} (entry ${chosen.entry.index}) is not among the kept run files`);
  let record;
  try { record = baselineRecord(JSON.parse(bytes.toString('utf8'))); } catch (error) { refuse('ledger-baseline-run-file-invalid', error.message); }
  if (record.core.id !== chosen.run.id || record.sha256 !== chosen.run.coreSha256) refuse('ledger-baseline-run-file-invalid', 'the kept run file is not the run the ledger records');
  await writeNew(copy, bytes);
  await writeNew(out, json({ ...base, state: 'selected', ledger: ledgerInfo,
    entry: chosen.entry.index, recordedAt: chosen.entry.recordedAt, runId: chosen.run.id, build: chosen.run.build ?? null, coreSha256: chosen.run.coreSha256, runFileSha256: digest,
    verdictsCheckedAgainstRunFiles: verified.verdictsCheckedAgainstRunFiles }));
  return copy;
}

const spawn = (file, args, options = {}) => new Promise(done => {
  execFile(file, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024, ...options }, (error, stdout, stderr) =>
    done({ code: error ? (typeof error.code === 'number' ? error.code : -1) : 0, stdout, stderr }));
});
const parsed = text => { try { return JSON.parse(text); } catch { return null; } };
const countLines = bytes => { const text = bytes.toString('utf8'); return text ? text.slice(0, -1).split('\n').length : 0; };
async function copyNew(from, to, limit, code) { await writeNew(to, await readRegular(from, limit, code)); }

/** After the export step: verify every signed export with the attest verifier, then append run.json's envelope to the ledger with
 * the ledger's own CLI and verify the ledger with it. Returns { state, reason, record }. */
export async function ciEvidence({ root, export: dir, runId, signingKeyDir, comparison = false, ledger, ledgerKeyDir, runFiles }) {
  absolute(root, '--root'); absolute(dir, '--export');
  const record = { schema: CI_EVIDENCE_SCHEMA, runId: runId || null, signing: null, ledger: null };
  const done = async (state, reason) => { await writeNew(join(dir, 'ci-evidence.json'), json({ ...record, state, reason })).catch(() => {}); return { state, reason, record }; };
  if (!runId || !UUID.test(runId)) return done('failed', 'no-saved-run');
  if (signingKeyDir) {
    const key = await keyPair(absolute(signingKeyDir, '--signing-key-dir'), 'signing-key-unsafe');
    await copyNew(key.publicPath, join(dir, PUBLIC_KEY_FILE), 16384, 'signing-key-unsafe');
    const names = [...SIGNED_EXPORTS, ...(comparison ? ['comparison.html'] : [])], envelopes = [];
    record.signing = { state: 'checking', publicKey: PUBLIC_KEY_FILE, envelopes };
    for (const name of names) {
      const result = await spawn(process.execPath, [join(root, 'integrations/attest/cli.mjs'), 'verify', '--key', join(dir, PUBLIC_KEY_FILE), '--envelope', join(dir, `${name}.dsse.json`), '--dir', dir]);
      const output = parsed(result.stdout);
      envelopes.push({ file: name, envelope: `${name}.dsse.json`, verdict: output?.verdict ?? 'unavailable', keyid: typeof output?.keyid === 'string' && HEX64.test(output.keyid) ? output.keyid : null });
      if (result.code !== 0 || output?.verdict !== 'verified') { record.signing.state = 'failed'; return done('failed', `signed-export-unverified:${name}`); }
    }
    record.signing.state = 'verified'; record.signing.keyid = envelopes[0].keyid;
  }
  if (ledger) {
    absolute(ledger, '--ledger'); absolute(runFiles, '--run-files');
    if (!signingKeyDir) return done('failed', 'ledger-needs-signing');
    const ledgerKey = await keyPair(absolute(ledgerKeyDir, '--ledger-key-dir'), 'ledger-key-unsafe');
    const evidencePublic = join(signingKeyDir, PUBLIC_KEY_FILE);
    await privateDirectory(runFiles, 'ledger-run-files-unsafe');
    await copyNew(ledgerKey.publicPath, join(dir, LEDGER_PUBLIC_KEY), 16384, 'ledger-key-unsafe');
    record.ledger = { state: 'appending', publicKey: LEDGER_PUBLIC_KEY };
    let before;
    try { before = countLines((await readLedgerFiles(ledger)).entries); } catch (error) { record.ledger.state = 'failed'; return done('failed', 'ledger-unreadable'); }
    // The run file is kept first (exclusively, by run id), so a run in the ledger always has its file for verify --run-files and
    // for a later ledger baseline. A refused append removes the copy it just made.
    const kept = join(runFiles, `${runId}.json`);
    try { await copyNew(join(dir, 'run.json'), kept, 8 * 1024 * 1024, 'run-file-not-kept'); }
    catch { record.ledger.state = 'failed'; return done('failed', 'run-file-not-kept'); }
    const cli = join(root, 'integrations/ledger/cli.mjs');
    const appended = await spawn(process.execPath, [cli, 'append', '--ledger', ledger, '--key', ledgerKey.privatePath, '--evidence-key', evidencePublic, '--envelope', join(dir, 'run.json.dsse.json'), '--dir', dir]);
    const append = parsed(appended.stdout);
    await writeNew(join(dir, 'ledger-append.json'), json(append ?? { error: 'unreadable output' })).catch(() => {});
    if (appended.code !== 0 || append?.appended !== true) {
      await unlink(kept).catch(() => {});
      record.ledger.state = 'failed'; record.ledger.appendExit = appended.code;
      return done('failed', 'ledger-append-refused');
    }
    const verifiedRun = await spawn(process.execPath, [cli, 'verify', '--ledger', ledger, '--key', ledgerKey.publicPath, '--evidence-key', evidencePublic, '--run-files', runFiles]);
    const verify = parsed(verifiedRun.stdout);
    await writeNew(join(dir, 'ledger-verify.json'), json(verify ?? { error: 'unreadable output' })).catch(() => {});
    Object.assign(record.ledger, { appendExit: appended.code, verifyExit: verifiedRun.code, index: append.index, envelopeSha256: append.envelope, lineSha256: append.lineSha256,
      log: verify?.log ?? null, size: verify?.size ?? null, covered: verify?.covered ?? null, rootHash: verify?.checkpoints?.at(-1)?.rootHash ?? null,
      verdict: verify?.verdict ?? 'unavailable', verdictsCheckedAgainstRunFiles: verify?.verdictsCheckedAgainstRunFiles ?? null, runs: verify?.runs ?? null, witness: 'none' });
    if (verifiedRun.code !== 0 || verify?.verdict !== 'verified') { record.ledger.state = 'failed'; return done('failed', 'ledger-verify-failed'); }
    if (verify.unsignedTail !== 0 || verify.covered !== verify.size || verify.size !== before + 1 || append.index !== before) { record.ledger.state = 'failed'; return done('failed', 'ledger-not-extended-by-one'); }
    record.ledger.state = 'appended';
  }
  return done('ok', '');
}

// ---- The job summary section ----

const safe = (value, pattern) => typeof value === 'string' && pattern.test(value) ? value : null;
const tick = value => value === null || value === undefined ? 'n/a' : `\`${value}\``;
export async function summary({ export: dir, ciState = '', ciReason = '' }) {
  const read = async name => { try { return JSON.parse((await readRegular(join(dir, name), 1024 * 1024, 'unreadable')).toString('utf8')); } catch { return null; } };
  const [lock, base, evidence] = await Promise.all([read('pack-lock.json'), read('ledger-baseline.json'), read('ci-evidence.json')]);
  if (!lock && !base && !evidence && !ciState) return '';
  const lines = ['', '### CI evidence', ''];
  if (evidence?.signing) {
    const s = evidence.signing;
    lines.push(`- **Signed exports:** ${s.state === 'verified' ? 'verified' : 'NOT verified'}; key id ${tick(safe(s.keyid, HEX64))}; ${s.envelopes.filter(e => e.verdict === 'verified').length} of ${s.envelopes.length} envelopes verified (${s.envelopes.map(e => `\`${safe(e.envelope, /^[a-z.]{1,40}$/) ?? '?'}\``).join(', ')}). The public key is \`${PUBLIC_KEY_FILE}\` in the evidence artifact; confirm its key id with the signer over a separate channel. A signature shows the key holder produced these bytes, not that the results are correct.`);
  }
  if (evidence?.ledger) {
    const l = evidence.ledger;
    lines.push(`- **Evidence ledger:** ${l.state === 'appended' ? `appended as entry ${Number.isSafeInteger(l.index) ? l.index : '?'}` : 'NOT appended'}; log ${tick(safe(l.log, UUID))}, size ${Number.isSafeInteger(l.size) ? l.size : 'n/a'}, root ${tick(safe(l.rootHash, HEX64))}, verify ${tick(safe(l.verdict, CODE))} (\`integrations/ledger/cli.mjs verify\` with the kept run files). Signed by the operator's ledger key only; not externally witnessed.`);
  }
  if (base) {
    lines.push(base.state === 'selected'
      ? `- **Baseline from the ledger:** entry ${Number.isSafeInteger(base.entry) ? base.entry : '?'}, run ${tick(safe(base.runId, UUID))}, build ${tick(safe(base.build, /^[A-Za-z0-9_.:-]{1,120}$/))}, core ${tick(safe(base.coreSha256, HEX64))}: the latest run of this target and application in the verified ledger.`
      : `- **Baseline from the ledger:** none (${tick(safe(base.reason, CODE))}); this run was assessed without a gate.`);
  }
  if (lock) {
    const packs = Array.isArray(lock.packs) ? lock.packs : [];
    lines.push(`- **Pinned packs:** lock ${tick(safe(lock.lockId, HEX64))} verified before any request (packs-v2 load check; checksums, not signatures).`);
    lines.push('', '| Pack | Version | Source | Manifest sha256 |', '| --- | --- | --- | --- |');
    for (const p of packs.slice(0, 50)) lines.push(`| ${tick(safe(p.name, /^[a-z][a-z0-9-]{1,47}$/))} | ${tick(safe(p.version, /^\d{1,3}\.\d{1,3}\.\d{1,3}$/))} | ${p.from === null ? 'shipped' : tick(safe(p.from, /^[A-Za-z0-9_./-]{1,120}$/))} | ${tick(safe(p.manifest, HEX64))} |`);
    lines.push('');
  }
  if (ciState && ciState !== 'ok') lines.push(`- **CI evidence failed:** ${tick(safe(ciReason.split(':')[0], CODE) ?? 'ci-evidence-unavailable')}. The job fails (exit 2).`);
  return `${lines.join('\n')}\n`;
}

export async function main(args) {
  const [command, ...rest] = args, options = {};
  const names = { '--profile': 'profile', '--lock': 'lock', '--out': 'out', '--ledger': 'ledger', '--ledger-key-dir': 'ledgerKeyDir', '--signing-key-dir': 'signingKeyDir',
    '--run-files': 'runFiles', '--target': 'target', '--copy': 'copy', '--root': 'root', '--export': 'export', '--run-id': 'runId', '--comparison': 'comparison',
    '--ci-state': 'ciState', '--ci-reason': 'ciReason' };
  for (let i = 0; i < rest.length; i += 2) {
    const key = names[rest[i]];
    if (!key || Object.hasOwn(options, key) || i + 1 >= rest.length) refuse('invalid-options', 'see the header of ci.mjs');
    options[key] = rest[i + 1];
  }
  if (command === 'pack-lock') return `${await packLock(options)}\n`;
  if (command === 'ledger-baseline') return `${await ledgerBaseline(options)}\n`;
  if (command === 'ci-evidence') {
    let result;
    try { result = await ciEvidence({ ...options, comparison: options.comparison === 'true', signingKeyDir: options.signingKeyDir || undefined, ledger: options.ledger || undefined }); }
    catch (error) {
      // A refusal before any record was written (an unsafe key folder, say) still yields a named failure for the job.
      console.error(`Scopehaven action: ${error?.message ?? 'ci-evidence error'}`);
      return `ci-state=failed\nci-reason=${CODE.test(error?.code ?? '') ? error.code : 'ci-evidence-error'}\n`;
    }
    const { state, reason, record } = result;
    const out = [`ci-state=${state}`, `ci-reason=${reason}`];
    if (record.ledger?.state === 'appended') out.push(`ledger-index=${record.ledger.index}`, `ledger-size=${record.ledger.size}`);
    return `${out.join('\n')}\n`;
  }
  if (command === 'summary') return summary(options);
  refuse('invalid-options', 'usage: ci.mjs pack-lock | ledger-baseline | ci-evidence | summary (see the header)');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const previous = process.umask(0o077);
  try { process.stdout.write(await main(process.argv.slice(2))); }
  catch (error) {
    const code = CODE.test(error?.code ?? '') ? error.code : 'ci-error';
    process.stdout.write(`${code}\n`);
    console.error(`Scopehaven action: ${error?.message ?? code}`);
    process.exitCode = 2;
  } finally { process.umask(previous); }
}
