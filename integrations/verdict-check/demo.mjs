// A check-it-yourself pack from the owned synthetic fixture. Local operator only.
//   node integrations/verdict-check/demo.mjs ABSOLUTE_NEW_DIR
// It writes two packs signed with one fresh key:
//   signed/  both demo builds, exported through the product's export path
//   forged/  the planted-defect build with one failing critical row relabelled pass, its assertions, counts and keyless
//            integrity hash recomputed: a forgery only the key holder could sign, and did
// Then it prints the commands that check each pack. The private key exists only in memory; only the public key is written.
// The directory must not exist yet: nothing is overwritten.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { digest } from '../../src/domain.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';

const out = process.argv[2];
if (process.argv.length !== 3 || !isAbsolute(out ?? '')) {
  console.error('Usage: node integrations/verdict-check/demo.mjs ABSOLUTE_NEW_DIR');
  process.exit(2);
}
await mkdir(out, { mode: 0o700 });
const dataDir = join(out, 'store'), signed = join(out, 'signed'), forged = join(out, 'forged'), publicKey = join(out, 'scopehaven-signing-key.pub.pem');
await mkdir(signed, { mode: 0o700 }); await mkdir(forged, { mode: 0o700 });
const store = createStore(dataDir); await store.ready;
const builds = { 'baseline.json': await runAssessment('demo-vulnerable'), 'repaired.json': await runAssessment('demo-repaired') };
for (const [name, run] of Object.entries(builds)) { await store.save(run); await exportRun({ runId: run.id, format: 'json', outputFile: join(signed, name), dataDir }); }

const key = generateSigningKey(), { version } = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
const sign = async (dir, files) => writeFile(join(dir, 'evidence.dsse.json'), signFiles(files, { privateKey: key.privatePem, version }).envelope, { mode: 0o644 });
await sign(signed, await Promise.all(Object.keys(builds).map(async name => ({ name, content: await readFile(join(signed, name)) }))));

const run = JSON.parse(await readFile(join(signed, 'baseline.json'), 'utf8')), row = run.results.find(r => r.status === 'fail' && r.severity === 'critical');
row.status = 'pass';
for (const assertion of row.assertions) assertion.status = 'pass';
for (const status of Object.keys(run.counts)) run.counts[status] = run.results.filter(r => r.status === status).length;
const { integrity: _integrity, notes: _notes, ...core } = run;
run.integrity.sha256 = digest(core);
const content = Buffer.from(`${JSON.stringify(run, null, 2)}\n`);
await writeFile(join(forged, 'baseline.json'), content, { mode: 0o600 });
await sign(forged, [{ name: 'baseline.json', content }]);
await writeFile(publicKey, key.publicPem, { mode: 0o644 });

const checker = fileURLToPath(new URL('./verify_verdicts.py', import.meta.url)), attest = fileURLToPath(new URL('../attest/verify_envelope.py', import.meta.url));
const command = (script, dir) => `python3 "${script}" --key "${publicKey}" --envelope "${join(dir, 'evidence.dsse.json')}" --dir "${dir}"`;
console.log(JSON.stringify({ keyid: key.keyid, forgedRow: row.id, commands: {
  'signed pack: every verdict re-derived (exit 0)': `${command(checker, signed)} --text`,
  'forged pack: the signature verifies (exit 0)': command(attest, forged),
  'forged pack: re-derivation refuses it (exit 1, verdict-mismatch)': `${command(checker, forged)} --text`,
} }, null, 2));
