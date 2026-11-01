// Retest history over a real ledger of real runs: ScopeHaven's owned HTTP lab in its baseline (vulnerable) and repaired builds,
// each run exported, signed and appended exactly as an operator would. Loopback and synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, chmod, readFile, writeFile, rm, appendFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { renderSarif } from '../../src/sarif.mjs';
import { createHttpLab, makeLabProfile } from '../../examples/http-lab.mjs';
import { initLedger, appendEnvelope } from '../ledger/ledger.mjs';
import { generateSigningKey } from '../attest/sign.mjs';
import { main, HISTORY_FILE, HISTORY_ENVELOPE } from './cli.mjs';
import { findingId, readDeclarations, retestHistory, DECLARATIONS_VERSION, HISTORY_VERSION } from './history.mjs';

const run = promisify(execFile);
const VERIFIER = fileURLToPath(new URL('../attest/verify_envelope.py', import.meta.url));
const KEY_FILE = 'scopehaven-signing-key.pem', PUB_FILE = 'scopehaven-signing-key.pub.pem';

async function privateDir(...parts) { const dir = join(...parts); await mkdir(dir, { recursive: true, mode: 0o700 }); await chmod(dir, 0o700); return dir; }

// One operator setup: a store, a signing key (exportRun makes it on first use), an export folder and a ledger.
async function operator(t) {
  const root = await mkdtemp(join(tmpdir(), 'retest ledger '));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const dirs = { root, store: await privateDir(root, 'store'), keys: await privateDir(root, 'keys'), exports: await privateDir(root, 'exports'), ledger: await privateDir(root, 'ledger') };
  await createStore(dirs.store).ready;
  await initLedger(dirs.ledger);
  const lab = await createHttpLab({ build: 'baseline' });
  t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  // Run the lab in a build, then export, sign and append the run, as the CLI does.
  const assess = async (build, { profile = p => p } = {}) => {
    lab.setBuild(build);
    const result = await runHttpAssessment(profile(makeLabProfile(lab.origin, `lab-${build}`)), { env });
    const saved = await createStore(dirs.store).save(result);
    const out = join(dirs.exports, `${saved.id}.json`);
    const exported = await exportRun({ runId: saved.id, format: 'json', outputFile: out, dataDir: dirs.store, signingKeyDir: dirs.keys, sign: true });
    const [envelope, bytes, priv, pub] = await Promise.all([readFile(exported.signature.envelope), readFile(out), readFile(join(dirs.keys, KEY_FILE), 'utf8'), readFile(join(dirs.keys, PUB_FILE), 'utf8')]);
    await appendEnvelope(dirs.ledger, { envelope, files: new Map([[`${saved.id}.json`, bytes]]), evidenceKey: pub, privateKey: priv });
    return saved;
  };
  const declare = async (findings = [], name = 'declarations.json') => { const path = join(root, name); await writeFile(path, JSON.stringify({ schema: DECLARATIONS_VERSION, customer: 'Owned lab', findings })); return path; };
  const options = declarations => ['--ledger', dirs.ledger, '--key', join(dirs.keys, PUB_FILE), '--run-files', dirs.exports, '--declarations', declarations];
  return { dirs, lab, assess, declare, options };
}
const lab = checkId => ({ applicationId: 'owned-http-lab', suiteId: undefined, checkId });
const byCheck = (history, checkId) => history.findings.find(f => f.checkId === checkId);

test('finding identity is the SARIF fingerprint scopehavenCheck/v1', async t => {
  const op = await operator(t);
  const saved = await op.assess('baseline');
  const sarif = renderSarif(saved);
  const results = sarif.runs[0].results;
  assert.ok(results.length > 0);
  for (const result of results) assert.equal(result.fingerprints['scopehavenCheck/v1'], findingId({ applicationId: saved.applicationId, suiteId: saved.suiteId, checkId: result.ruleId }), result.ruleId);
  // Every failing row's finding id appears among the SARIF fingerprints.
  const prints = new Set(results.map(r => r.fingerprints['scopehavenCheck/v1']));
  for (const row of saved.results.filter(r => r.status === 'fail')) assert.ok(prints.has(findingId({ applicationId: saved.applicationId, suiteId: saved.suiteId, checkId: row.id })), row.id);
});

test('found, FIXED_VERIFIED, regressed and FIXED_VERIFIED again across real lab builds; an observer-less backend row is never credited', async t => {
  const op = await operator(t);
  const runs = [await op.assess('baseline'), await op.assess('repaired'), await op.assess('baseline'), await op.assess('repaired')];
  assert.equal(runs[0].results.find(r => r.id === 'FOREIGN-STATUS').status, 'fail');
  assert.equal(runs[1].results.find(r => r.id === 'FOREIGN-STATUS').status, 'pass');
  const declarations = await op.declare([{ ...lab('FOREIGN-STATUS'), class: 'B2', twins: ['OWN-RECORD'] }].map(({ suiteId, ...f }) => ({ ...f, suiteId: runs[0].suiteId })));
  const { code, output } = await main(['build', ...op.options(declarations)]);
  assert.equal(code, 0, JSON.stringify(output));
  assert.equal(output.schema, HISTORY_VERSION);
  assert.equal(output.runs, 4);
  const foreign = byCheck(output, 'FOREIGN-STATUS');
  assert.deepEqual(foreign.events.map(e => e.state), ['found', 'FIXED_VERIFIED', 'regressed', 'FIXED_VERIFIED']);
  assert.equal(foreign.state, 'FIXED_VERIFIED'); assert.equal(foreign.open, false); assert.equal(foreign.class, 'B2');
  assert.equal(foreign.events[1].baselineRunId, runs[0].id); assert.equal(foreign.events[1].transition, 'contract-restored');
  assert.equal(foreign.events[3].baselineRunId, runs[2].id);
  // The backend row fails in the baseline (a fail decides without an observer) but its repaired pass cannot: no verified repair.
  const backend = byCheck(output, 'BACKEND-UNVERIFIED');
  assert.equal(backend.state, 'NO_VERIFIED_REPAIR'); assert.equal(backend.open, true);
  assert.match(backend.events[1].reason, /core reads the row as unverified|status inconclusive/);
  assert.equal(output.counts.findings, output.findings.length);
  assert.equal(output.counts.FIXED_VERIFIED, 1);
});

test('fix claims: a claimed build still failing reads NO_VERIFIED_REPAIR, a build with no run stays fix-claimed, a failing twin blocks the credit', async t => {
  const op = await operator(t);
  const first = await op.assess('baseline');
  await op.assess('baseline', { profile: p => ({ ...p, buildLabel: 'lab-claimed-fix' }) });
  await op.assess('repaired');
  const suiteId = first.suiteId;
  const declarations = await op.declare([
    { applicationId: 'owned-http-lab', suiteId, checkId: 'FOREIGN-STATUS', fixClaims: [{ build: 'lab-claimed-fix' }], twins: ['BACKEND-UNVERIFIED'], openReason: 'twin is undecided without an observer' },
    { applicationId: 'owned-http-lab', suiteId, checkId: 'ANONYMOUS', fixClaims: [{ build: 'never-run' }] },
    { applicationId: 'owned-http-lab', suiteId, checkId: 'BACKEND-UNVERIFIED', fixClaims: [{ build: 'lab-next' }] },
  ]);
  const { code, output } = await main(['build', ...op.options(declarations)]);
  assert.equal(code, 0, JSON.stringify(output));
  const foreign = byCheck(output, 'FOREIGN-STATUS');
  assert.deepEqual(foreign.events.map(e => [e.state, e.source]), [['found', 'run'], ['fix-claimed', 'declared'], ['NO_VERIFIED_REPAIR', 'run'], ['NO_VERIFIED_REPAIR', 'run']]);
  assert.match(foreign.events[2].reason, /Still failing in the claimed build/);
  assert.match(foreign.events[3].reason, /declared twin BACKEND-UNVERIFIED did not pass/);
  assert.equal(foreign.openReason, 'twin is undecided without an observer');
  // A claim on a build the ledger has no run of leaves the finding fix-claimed, with no run named.
  const backend = byCheck(output, 'BACKEND-UNVERIFIED');
  assert.equal(backend.state, 'fix-claimed'); assert.equal(backend.open, true);
  assert.deepEqual(backend.events.at(-1), { state: 'fix-claimed', source: 'declared', entry: null, runId: null, recordedAt: null, build: 'lab-next', reason: 'The operator declared a fix in this build; no run of it is in the ledger yet.' });
  // A declaration for a check that never failed adds no finding.
  assert.equal(byCheck(output, 'ANONYMOUS'), undefined);
  assert.equal(output.declaredFindingsNotSeen, 1);
});

test('an incompatible pair never verifies, and core\'s reason is carried', async t => {
  const op = await operator(t);
  await op.assess('baseline');
  await op.assess('repaired', { profile: p => ({ ...p, contextId: 'synthetic-records-v2' }) });
  const { code, output } = await main(['build', ...op.options(await op.declare())]);
  assert.equal(code, 0);
  const foreign = byCheck(output, 'FOREIGN-STATUS');
  assert.equal(foreign.state, 'NO_VERIFIED_REPAIR');
  assert.match(foreign.events[1].reason, /not comparable \(.*differs/);
  assert.equal(foreign.events[1].runLevelVerdict, 'INCONCLUSIVE');
});

test('signed export verifies with both verifiers and reproduces; an edited history or a wrong key is rejected', async t => {
  const op = await operator(t);
  await op.assess('baseline'); await op.assess('repaired');
  const declarations = await op.declare();
  const out = join(op.dirs.root, 'history');
  const exported = await main(['export', ...op.options(declarations), '--out', out, '--signing-key-dir', op.dirs.keys]);
  assert.equal(exported.code, 0, JSON.stringify(exported.output));
  const py = await run('python3', ['-I', VERIFIER, '--key', join(out, PUB_FILE), '--envelope', join(out, HISTORY_ENVELOPE), '--dir', out]);
  assert.equal(JSON.parse(py.stdout).verdict, 'verified');
  const node = await run(process.execPath, [fileURLToPath(new URL('../attest/cli.mjs', import.meta.url)), 'verify', '--key', join(out, PUB_FILE), '--envelope', join(out, HISTORY_ENVELOPE), '--dir', out]);
  assert.equal(JSON.parse(node.stdout).verdict, 'verified');
  const verified = await main(['verify', ...op.options(declarations), '--history', out]);
  assert.equal(verified.code, 0); assert.equal(verified.output.verdict, 'reproduced');
  // Two builds from the same inputs give the same bytes.
  const again = await main(['build', ...op.options(declarations)]);
  assert.equal(`${JSON.stringify(again.output, null, 2)}\n`, await readFile(join(out, HISTORY_FILE), 'utf8'));
  // Edit the history: the signature no longer verifies.
  const edited = join(op.dirs.root, 'edited');
  await privateDir(edited);
  for (const name of [HISTORY_ENVELOPE, PUB_FILE]) await writeFile(join(edited, name), await readFile(join(out, name)));
  await writeFile(join(edited, HISTORY_FILE), (await readFile(join(out, HISTORY_FILE), 'utf8')).replace('"NO_VERIFIED_REPAIR"', '"FIXED_VERIFIED"').replace('"found"', '"FIXED_VERIFIED"'));
  const rejected = await main(['verify', ...op.options(declarations), '--history', edited]);
  assert.equal(rejected.code, 1); assert.equal(rejected.output.verdict, 'rejected');
  // A history signed by another key over different declarations: the signature verifies under that key, but the rebuild differs.
  const other = generateSigningKey(), otherKeys = await privateDir(op.dirs.root, 'other-keys');
  await writeFile(join(otherKeys, KEY_FILE), other.privatePem, { mode: 0o600 }); await writeFile(join(otherKeys, PUB_FILE), other.publicPem);
  const out2 = join(op.dirs.root, 'history2');
  const declared2 = await op.declare([{ applicationId: 'owned-http-lab', suiteId: (await main(['build', ...op.options(declarations)])).output.findings[0].suiteId, checkId: 'FOREIGN-STATUS', class: 'B2' }], 'declarations2.json');
  assert.equal((await main(['export', ...op.options(declared2), '--out', out2, '--signing-key-dir', otherKeys])).code, 0);
  const mismatch = await main(['verify', ...op.options(declarations), '--history', out2]);
  assert.equal(mismatch.output.verdict, 'not-reproduced'); assert.equal(mismatch.code, 1);
  // --out that exists is refused before anything is written.
  await assert.rejects(main(['export', ...op.options(declarations), '--out', out, '--signing-key-dir', op.dirs.keys]), /already exists/);
});

test('refusals: an unverified ledger, a missing run file, open findings without reasons, malformed declarations', async t => {
  const op = await operator(t);
  const first = await op.assess('baseline'); await op.assess('repaired');
  const declarations = await op.declare();
  // --require-reasons: FOREIGN-STATUS is fixed, BACKEND-UNVERIFIED stays open with no reason.
  const strict = await main(['build', ...op.options(declarations), '--require-reasons']);
  assert.equal(strict.code, 1); assert.equal(strict.output.reason, 'open-without-reason');
  const reasoned = await op.declare([{ applicationId: 'owned-http-lab', suiteId: first.suiteId, checkId: 'BACKEND-UNVERIFIED', openReason: 'no observer for the backend row' }], 'reasoned.json');
  assert.equal((await main(['build', ...op.options(reasoned), '--require-reasons'])).code, 0);
  // A run file missing from the folder.
  const { readdir, rename } = await import('node:fs/promises');
  const runFile = (await readdir(op.dirs.exports)).find(n => n.startsWith(first.id) && !n.endsWith('.dsse.json'));
  await rename(join(op.dirs.exports, runFile), join(op.dirs.root, runFile));
  const missing = await main(['build', ...op.options(declarations)]);
  assert.equal(missing.code, 1); assert.match(missing.output.detail, /no run file for ledger run|checked against its signed run file/);
  await rename(join(op.dirs.root, runFile), join(op.dirs.exports, runFile));
  // A tampered ledger entry.
  const entries = join(op.dirs.ledger, 'entries.jsonl'), original = await readFile(entries, 'utf8');
  await writeFile(entries, original.replace('"fail"', '"pass"'));
  const tampered = await main(['build', ...op.options(declarations)]);
  assert.equal(tampered.code, 1); assert.equal(tampered.output.verdict, 'rejected');
  await writeFile(entries, original);
  // An unsigned tail: a line appended with no checkpoint over it.
  await appendFile(entries, original.split('\n')[0] + '\n');
  assert.equal((await main(['build', ...op.options(declarations)])).code, 1);
  await writeFile(entries, original);
  // Declarations.
  for (const bad of [
    { schema: 'other' },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [], extra: 1 },
    { schema: DECLARATIONS_VERSION, customer: '<script>', findings: [] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c', openReason: 'see https://example.com' }] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c', class: 'a4' }] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c', twins: ['c'] }] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c' }, { applicationId: 'a', suiteId: 's', checkId: 'c' }] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c', fixClaims: [{ build: 'b', note: 'x' }] }] },
    { schema: DECLARATIONS_VERSION, customer: 'x', findings: [{ applicationId: 'a', suiteId: 's', checkId: 'c', state: 'FIXED_VERIFIED' }] },
  ]) assert.throws(() => readDeclarations(bad), /retest-history-refused/, JSON.stringify(bad));
  // Usage: relative paths and unknown flags.
  await assert.rejects(main(['build', '--ledger', 'relative', '--key', '/k', '--run-files', '/r', '--declarations', '/d']), /absolute/);
  await assert.rejects(main(['build', ...op.options(declarations), '--surprise', '/x']), /Usage/);
  // History is built only from a verified ledger result.
  assert.throws(() => retestHistory({ verdict: 'rejected' }, [], null), /verified ledger/);
});

// A verified-ledger result over in-memory runs, so a test can hand the history runs that carry a model identity. The binding
// rules are the same ones a real ledger goes through (coreSha256 and verdicts per run, every run checked).
function verifiedOf(runs) {
  return { ledger: 'scopehaven-ledger/1', verdict: 'verified', unsignedTail: 0, runs: runs.length, verdictsCheckedAgainstRunFiles: runs.length, log: 'test-log', covered: runs.length,
    checkpoints: [{ treeSize: runs.length, rootHash: '0'.repeat(64), signedAt: '2026-10-26T00:00:00.000Z' }],
    entries: runs.map((run, index) => ({ index, recordedAt: `2026-10-26T00:00:0${index}.000Z`, runs: [{ id: run.id, coreSha256: `${index}`.repeat(64), verdicts: run.results.map(r => [r.id, r.status]) }] })) };
}
const filesOf = runs => runs.map((core, index) => ({ core, coreSha256: `${index}`.repeat(64) }));
let tapSessions = 0;
const modelIdentity = (served, weightsDigest) => ({ schema: 'scopehaven-model-identity/2', state: 'observed', strength: 'weights-digest', tapSession: `session-${++tapSessions}`,
  upstream: 'http://127.0.0.1:11434', upstreamKind: 'loopback', window: { from: 0, to: null }, calls: { total: 3, succeeded: 3, failed: 0, abandoned: 0 }, reasons: [],
  models: [{ served, requested: [served], fingerprints: [], weightsDigest, apis: ['ollama-chat'], calls: 3, strength: 'weights-digest' }] });

test('a pass core credits to a model change, or to an unreadable model identity, is never FIXED_VERIFIED', async t => {
  const lab = await createHttpLab({ build: 'baseline' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const before = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  lab.setBuild('repaired');
  const sameLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const newLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  const [A, B] = ['a'.repeat(64), 'b'.repeat(64)];
  const foreign = runs => byCheck(retestHistory(verifiedOf(runs), filesOf(runs), null), 'FOREIGN-STATUS');
  // The model changed between the runs: core does not credit the application.
  const swapped = foreign([{ ...before, modelIdentity: modelIdentity('model-x', A) }, { ...sameLabel, modelIdentity: modelIdentity('model-y', B) }]);
  assert.equal(swapped.state, 'NO_VERIFIED_REPAIR'); assert.equal(swapped.open, true);
  assert.match(swapped.events[1].reason, /core does not credit the repair to the application|not the application/);
  // One side's model identity cannot be read.
  const unreadable = foreign([{ ...before, modelIdentity: { state: 'observed', models: 'garbled' } }, { ...newLabel, modelIdentity: modelIdentity('model-x', A) }]);
  assert.equal(unreadable.state, 'NO_VERIFIED_REPAIR'); assert.match(unreadable.events[1].reason, /could not be read/);
  // The same model on both sides and a new build label: the repair is the application's.
  const app = foreign([{ ...before, modelIdentity: modelIdentity('model-x', A) }, { ...newLabel, modelIdentity: modelIdentity('model-x', A) }]);
  assert.equal(app.state, 'FIXED_VERIFIED', JSON.stringify(app.events));
});

test('a fix claim never hides a regression and is consumed by its build whatever the state', async t => {
  const op = await operator(t);
  const build = name => p => ({ ...p, buildLabel: name });
  const first = await op.assess('baseline', { profile: build('lab-b1') });
  await op.assess('repaired', { profile: build('lab-b2') });
  await op.assess('baseline', { profile: build('lab-b3') });
  const declarations = await op.declare([{ applicationId: 'owned-http-lab', suiteId: first.suiteId, checkId: 'FOREIGN-STATUS', fixClaims: [{ build: 'lab-b3' }, { build: 'lab-b1' }, { build: 'lab-b9' }] }]);
  const { code, output } = await main(['build', ...op.options(declarations)]);
  assert.equal(code, 0, JSON.stringify(output));
  const foreign = byCheck(output, 'FOREIGN-STATUS');
  // b3's claim arrived while the finding was FIXED_VERIFIED: consumed with no event. b1 was run before (it is where the finding
  // was found): ignored. b9 has no run: its event is recorded, and the computed regressed state stays.
  assert.deepEqual(foreign.events.map(e => [e.state, e.source, e.build]), [['found', 'run', 'lab-b1'], ['FIXED_VERIFIED', 'run', 'lab-b2'], ['regressed', 'run', 'lab-b3'], ['fix-claimed', 'declared', 'lab-b9']]);
  assert.equal(foreign.state, 'regressed'); assert.equal(output.counts.regressed, 1); assert.equal(output.counts['fix-claimed'], 0);
  assert.equal(foreign.regressions, 1); assert.equal(output.counts.regressedEver, 1);
  // The history exports and signs; the assessor pack that reads it is not part of the open edition.
  const out = join(op.dirs.root, 'regressed-history');
  assert.equal((await main(['export', ...op.options(declarations), '--out', out, '--signing-key-dir', op.dirs.keys])).code, 0);
});

test('ordering: runs out of creation order are refused, a pass no later than its fail is not credited, and a verified fix reopens when a later run does not pass or drops the check', async t => {
  const lab = await createHttpLab({ build: 'baseline' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const r1 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const r3 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  lab.setBuild('repaired');
  const r2 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  const at = (run, ms) => ({ ...run, createdAt: new Date(Date.parse('2026-10-26T10:00:00.000Z') + ms).toISOString() });
  const history = runs => retestHistory(verifiedOf(runs), filesOf(runs), null);
  // The reviewer's case: R1 fail (t1), R3 fail (t3), then R2 pass (t2) appended last: refused, never FIXED_VERIFIED.
  assert.throws(() => history([at(r1, 1000), at(r3, 3000), at(r2, 2000)]), /made before an earlier entry's run/);
  // A run with no readable time is refused.
  assert.throws(() => history([at(r1, 1000), { ...r2, createdAt: 'yesterday' }]), /no readable createdAt/);
  // Same time: allowed in the ledger, but the pass is not after the fail, so no repair is credited.
  const same = byCheck(history([at(r1, 1000), at(r2, 1000)]), 'FOREIGN-STATUS');
  assert.equal(same.state, 'NO_VERIFIED_REPAIR'); assert.match(same.events[1].reason, /not made after the run that failed/);
  // In order, the fix verifies; a later run that reads the check inconclusive reopens it, and a later pass verifies it again.
  const inconclusive = run => ({ ...run, results: run.results.map(r => r.id === 'FOREIGN-STATUS' ? { ...r, status: 'inconclusive' } : r) });
  const reopened = byCheck(history([at(r1, 1000), at(r2, 2000), at(inconclusive(r2), 3000), at(r2, 4000)]), 'FOREIGN-STATUS');
  assert.deepEqual(reopened.events.map(e => e.state), ['found', 'FIXED_VERIFIED', 'NO_VERIFIED_REPAIR', 'FIXED_VERIFIED']);
  assert.match(reopened.events[2].reason, /read the check as inconclusive/);
  // A later run of the same application and suite without the check reopens it too.
  const dropped = { ...r2, results: r2.results.filter(r => r.id !== 'FOREIGN-STATUS') };
  const gone = byCheck(history([at(r1, 1000), at(r2, 2000), at(dropped, 3000)]), 'FOREIGN-STATUS');
  assert.equal(gone.state, 'NO_VERIFIED_REPAIR'); assert.equal(gone.open, true); assert.match(gone.events.at(-1).reason, /does not carry the check/);
  // A fail after a reopened fix is still a regression: b1 fail, b2 pass, b3 inconclusive (or without the check), b4 fail.
  for (const b3 of [inconclusive(r2), dropped]) {
    const regressed = retestHistory(verifiedOf([at(r1, 1000), at(r2, 2000), at(b3, 3000), at(r3, 4000)]), filesOf([at(r1, 1000), at(r2, 2000), at(b3, 3000), at(r3, 4000)]), null);
    const f = byCheck(regressed, 'FOREIGN-STATUS');
    assert.deepEqual(f.events.map(e => e.state), ['found', 'FIXED_VERIFIED', 'NO_VERIFIED_REPAIR', 'regressed']);
    assert.equal(f.state, 'regressed'); assert.equal(f.regressions, 1); assert.equal(regressed.counts.regressedEver, 1);
  }
});

test('a regression answers an open fix claim: the next failing run adds no "still failing in the claimed build" event', async t => {
  const lab = await createHttpLab({ build: 'baseline' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const r1 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const r3 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  lab.setBuild('repaired');
  const r2 = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  const at = (run, ms, build = run.build) => ({ ...run, build, createdAt: new Date(Date.parse('2026-10-26T10:00:00.000Z') + ms).toISOString() });
  const inconclusive = run => ({ ...run, results: run.results.map(r => r.id === 'FOREIGN-STATUS' ? { ...r, status: 'inconclusive' } : r) });
  const declarations = readDeclarations({ schema: DECLARATIONS_VERSION, customer: 'Owned lab', findings: [{ applicationId: r1.applicationId, suiteId: r1.suiteId, checkId: 'FOREIGN-STATUS', fixClaims: [{ build: 'lab-v3' }] }] });
  const history = runs => byCheck(retestHistory(verifiedOf(runs), filesOf(runs), declarations), 'FOREIGN-STATUS');
  // A reopened fix (b1 fail, b2 pass, then a run that reads the check inconclusive or does not carry it), the operator claims a fix
  // in b3, b3 fails (regressed), b4 fails again: the regression answered the claim, so b4 adds no event.
  const dropped = run => ({ ...run, results: run.results.filter(r => r.id !== 'FOREIGN-STATUS') });
  for (const [name, reopen] of [['inconclusive', inconclusive], ['dropped', dropped]]) {
    const f = history([at(r1, 1000), at(r2, 2000), at(reopen(r2), 3000), at(r3, 4000, 'lab-v3'), at(r3, 5000, 'lab-v4')]);
    assert.deepEqual(f.events.map(e => [e.state, e.source, e.build]), [['found', 'run', 'lab-v1'], ['FIXED_VERIFIED', 'run', 'lab-v2'], ['NO_VERIFIED_REPAIR', 'run', 'lab-v2'],
      ['fix-claimed', 'declared', 'lab-v3'], ['regressed', 'run', 'lab-v3']], name);
    assert.ok(!f.events.some(e => /claimed build/.test(e.reason)), `${name}: ${JSON.stringify(f.events)}`);
    assert.equal(f.state, 'regressed', name); assert.equal(f.regressions, 1, name);
  }
});
