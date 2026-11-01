// CI mode of the Scopehaven GitHub Action: sign, ledger-dir (with ledger-key-dir and ledger-run-files), baseline-from-ledger and
// pack-lock. node:test, zero dependencies, loopback only: the owned synthetic HTTP lab runs in-process and action.yml's run steps
// are executed by harness.mjs (uses: steps are skipped, so nothing is uploaded or sent). Keys and ledgers live in a temporary
// folder and are made with integrations/attest/cli.mjs keygen and integrations/ledger/cli.mjs init.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { appendFile, chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createHttpLab, makeLabProfile, makeLabAuthorization } from '../../examples/http-lab.mjs';
import { here, loadAction, run, runAction } from './harness.mjs';
import { PACK } from './ci-proof.mjs';
import { summary } from './ci.mjs';

const root = resolve(here, '../..');
const node = process.execPath;
const CI_INPUTS = ['sign', 'signing-key-dir', 'ledger-dir', 'ledger-key-dir', 'ledger-run-files', 'baseline-from-ledger', 'pack-lock'];
let lab, scratch, workspace, runnerTemp, env, keys, profileFile;
const log = result => result.logs.map(entry => `${entry.stdout ?? ''}${entry.stderr ?? ''}`).join('\n');
const must = async (promise, what) => { const result = await promise; assert.equal(result.code, 0, `${what}: ${result.stdout}${result.stderr}`); return result; };
const privateDir = async path => { await mkdir(path, { recursive: true, mode: 0o700 }); await chmod(path, 0o700); return path; };
async function newLedger(name) {
  const dir = await privateDir(join(scratch, 'ledgers', name)), runFiles = await privateDir(join(scratch, 'ledgers', `${name}-runs`));
  await must(run(node, [join(root, 'integrations/ledger/cli.mjs'), 'init', '--ledger', dir], { env }), 'ledger init');
  return { dir, runFiles };
}
const ciInputs = ledger => ({ sign: 'true', 'signing-key-dir': keys.evidence, ...(ledger ? { 'ledger-dir': ledger.dir, 'ledger-key-dir': keys.ledger, 'ledger-run-files': ledger.runFiles } : {}) });
const base = () => ({ profile: 'app/targets.json', authorization: 'app/authorization.json', 'wait-url': `${lab.origin}/me`, 'wait-timeout-seconds': '10' });

before(async () => {
  scratch = await mkdtemp(join(tmpdir(), 'scopehaven-ci-mode-test-'));
  await chmod(scratch, 0o700);
  workspace = await privateDir(join(scratch, 'workspace')); runnerTemp = await privateDir(join(scratch, 'runner-temp'));
  env = { PATH: `${dirname(node)}:/usr/bin:/bin`, HOME: scratch, TMPDIR: scratch, SCOPEHAVEN_NODE: node };
  keys = { evidence: await privateDir(join(scratch, 'keys/evidence')), ledger: await privateDir(join(scratch, 'keys/ledger')) };
  for (const dir of Object.values(keys)) await must(run(node, [join(root, 'integrations/attest/cli.mjs'), 'keygen', '--dir', dir], { env }), 'keygen');
  lab = await createHttpLab({ build: 'repaired' });
  env.SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN = lab.memberToken;
  // The app's profile: the lab profile without its backend-required row (a response-only run keeps it inconclusive), plus an
  // operator pack read from app/packs and locked beside the profile.
  const app = await privateDir(join(workspace, 'app')), packDir = await privateDir(join(app, 'packs/lab-record-access'));
  for (const [name, value] of Object.entries(PACK)) await writeFile(join(packDir, name), JSON.stringify(value, null, 2));
  await must(run(node, [join(root, 'integrations/packs-v2/cli.mjs'), 'seal', packDir], { env }), 'pack seal');
  const profile = makeLabProfile(lab.origin, 'ci-mode-test');
  profile.checks = profile.checks.filter(check => check.id !== 'BACKEND-UNVERIFIED');
  profile.checks.push({ pack: 'LR' });
  profile.packs = [{ name: 'lab-record-access', version: '1.0.0', as: 'LR', from: 'packs', params: { actor: 'member', ownPath: '/records/own', foreignPath: '/records/foreign' } }];
  profileFile = join(app, 'targets.json');
  await writeFile(profileFile, JSON.stringify({ schemaVersion: 1, targets: [profile] }, null, 2));
  await writeFile(join(app, 'authorization.json'), JSON.stringify(makeLabAuthorization(lab.origin)));
  await must(run(node, [join(root, 'integrations/packs-v2/cli.mjs'), 'lock', '--config', profileFile], { env }), 'pack lock');
  // The same profile without packs, for the pack-lock-unused refusal.
  const plain = makeLabProfile(lab.origin, 'ci-mode-test'); plain.checks = plain.checks.filter(check => check.id !== 'BACKEND-UNVERIFIED');
  await privateDir(join(workspace, 'plain'));
  await writeFile(join(workspace, 'plain/targets.json'), JSON.stringify({ schemaVersion: 1, targets: [plain] }));
  await writeFile(join(workspace, 'plain/scopehaven.lock'), await readFile(join(app, 'scopehaven.lock')));
});
after(async () => { await lab?.close(); if (scratch) await rm(scratch, { recursive: true, force: true }); });

test('the CI inputs exist and default off, and the export step stays unsigned unless sign is on', async () => {
  const { text, action } = await loadAction();
  for (const key of CI_INPUTS) assert.ok(Object.hasOwn(action.inputs, key), key);
  assert.equal(action.inputs.sign.default, 'false');
  assert.equal(action.inputs['baseline-from-ledger'].default, 'false');
  for (const key of ['signing-key-dir', 'ledger-dir', 'ledger-key-dir', 'ledger-run-files', 'pack-lock']) assert.equal(action.inputs[key].default, '', key);
  assert.match(text, /sign_args=\(--unsigned\)\n\s+if \[ -n "\$SH_SIGNING_KEY_DIR" \]; then sign_args=\(--signing-key-dir "\$SH_SIGNING_KEY_DIR"\); fi/);
  assert.equal((text.match(/--data "\$SH_STORE" "\$\{sign_args\[@\]\}"/g) ?? []).length, 4, 'every export line takes the signing arguments');
  assert.doesNotMatch(text, /--data "\$SH_STORE" --unsigned/);
  // The ledger is written only through its own CLI, from ci.mjs; the action never runs init.
  assert.doesNotMatch(text, /ledger\/cli\.mjs" init|cli\.mjs init --ledger/);
  assert.equal(await summary({ export: scratch }), '', 'no CI section without CI records');
});

test('off: a default run writes no envelope, no ledger record and no CI section', async () => {
  const result = await runAction({ ...base(), 'fail-on': 'never' }, { workspace, runnerTemp, env });
  assert.equal(result.steps.prepare.outcome, 'success', log(result));
  assert.equal(result.steps.ci.outcome, 'success');
  assert.match(log(result), /no signing or ledger requested/);
  const exported = (await readdir(join(result.steps.prepare.outputs.work, 'export'))).sort();
  // pack-status.json: pack-updates defaults to report, and this profile uses a pack (a status record only; no CI record).
  assert.deepEqual(exported, ['pack-status.json', 'report.html', 'run.json', 'scopehaven.sarif', 'summary.md']);
  assert.doesNotMatch(result.summary, /### CI evidence/);
  assert.equal(result.exitCode, 0);
});

test('refusals: invalid or incomplete CI inputs stop in the prepare step, before the wait or any request', async () => {
  const ledger = await newLedger('refusals');
  const notInitialized = await privateDir(join(scratch, 'ledgers/not-initialized'));
  const noKey = await privateDir(join(scratch, 'keys/empty'));
  for (const [name, inputs, message] of [
    ['sign not a boolean', { sign: 'yes' }, /sign must be true or false/],
    ['sign without a key folder', { sign: 'true' }, /sign needs signing-key-dir/],
    ['a key folder without sign', { 'signing-key-dir': keys.evidence }, /signing-key-dir needs sign: true/],
    ['a relative key folder', { sign: 'true', 'signing-key-dir': 'keys/evidence' }, /signing-key-dir must be an absolute path/],
    ['a key folder without a key (the action never makes one)', { sign: 'true', 'signing-key-dir': noKey }, /must hold scopehaven-signing-key\.pem .*never creates a key/],
    ['sign with report-only', { ...ciInputs(), 'report-only': 'true', 'report-only-until': new Date(Date.now() + 86400000).toISOString().slice(0, 10) }, /sign cannot be combined with report-only/],
    ['a ledger without sign', { 'ledger-dir': ledger.dir, 'ledger-key-dir': keys.ledger, 'ledger-run-files': ledger.runFiles }, /ledger-dir needs sign: true/],
    ['a ledger without its key folder', { ...ciInputs(), 'ledger-dir': ledger.dir, 'ledger-run-files': ledger.runFiles }, /set ledger-dir, ledger-key-dir and ledger-run-files together/],
    ['a ledger folder that was never initialized', { ...ciInputs({ dir: notInitialized, runFiles: ledger.runFiles }) }, /must be an initialized ledger .*never starts a new ledger/],
    ['baseline-from-ledger without a ledger', { 'baseline-from-ledger': 'true' }, /baseline-from-ledger needs ledger-dir/],
    ['baseline-from-ledger not a boolean', { 'baseline-from-ledger': 'on' }, /baseline-from-ledger must be true or false/],
    ['baseline-from-ledger with baseline-run', { ...ciInputs(ledger), 'baseline-from-ledger': 'true', 'baseline-run': 'app/targets.json' }, /set baseline-run or baseline-from-ledger, not both/],
    ['baseline-from-ledger with trials', { ...ciInputs(ledger), 'baseline-from-ledger': 'true', trials: '3' }, /trials needs baseline-run/],
    ['baseline-from-ledger with single-identity', { ...ciInputs(ledger), 'baseline-from-ledger': 'true', 'single-identity': 'true' }, /single-identity applies to the assess mode only/],
    ['a pack lock that does not exist', { 'pack-lock': 'app/missing.lock' }, /pack-lock must be an existing regular file/],
    ['a pack lock that is not the one beside the profile', { 'pack-lock': 'plain/scopehaven.lock' }, /pack lock refused \(pack-lock-not-beside-profile\)/],
    ['a pack lock for a profile that references no packs', { profile: 'plain/targets.json', 'pack-lock': 'plain/scopehaven.lock' }, /pack lock refused \(pack-lock-unused\)/],
    // A pull takes newer pack versions than the pinned lock and the ledger baseline were taken with: refused with either.
    ['pack-updates pull with pack-lock', { 'pack-updates': 'pull', 'pack-lock': 'app/scopehaven.lock' }, /pack-updates pull cannot be combined with pack-lock or baseline-from-ledger/],
    ['pack-updates pull with baseline-from-ledger', { ...ciInputs(ledger), 'baseline-from-ledger': 'true', 'pack-updates': 'pull' }, /pack-updates pull cannot be combined with pack-lock or baseline-from-ledger/],
  ]) {
    const result = await runAction({ ...base(), ...inputs }, { workspace, runnerTemp, env });
    assert.equal(result.steps.prepare.outcome, 'failure', name);
    assert.match(log(result), message, name);
    assert.deepEqual([result.steps.wait.outcome, result.steps.assess.outcome, result.steps.ci.outcome], ['skipped', 'skipped', 'skipped'], name);
    assert.equal(result.outputs['run-id'] ?? '', '', name);
    assert.notEqual(result.exitCode, 0, name);
  }
  // Nothing was appended to the ledger by any refused run.
  assert.equal(await readFile(join(ledger.dir, 'entries.jsonl'), 'utf8'), '');
});

test('pack-lock on: the lock is verified before any request and the pinned packs are recorded; an edited pack is refused', async () => {
  const result = await runAction({ ...base(), 'pack-lock': 'app/scopehaven.lock' }, { workspace, runnerTemp, env });
  assert.equal(result.exitCode, 0, log(result));
  const record = JSON.parse(await readFile(join(result.steps.prepare.outputs.work, 'export/pack-lock.json'), 'utf8'));
  const lock = JSON.parse(await readFile(join(workspace, 'app/scopehaven.lock'), 'utf8'));
  assert.equal(record.lockId, lock.lockId);
  assert.equal(result.steps.prepare.outputs['pack-lock-id'], lock.lockId);
  assert.deepEqual(record.packs.map(p => [p.name, p.version, p.from, p.manifest]), lock.packs.map(p => [p.name, p.version, p.from, p.manifest]));
  assert.deepEqual(record.referenced, [{ target: 'http-lab', name: 'lab-record-access', version: '1.0.0', as: 'LR', from: 'packs' }]);
  assert.match(result.summary, /\*\*Pinned packs:\*\* lock `[0-9a-f]{64}` verified before any request/);
  assert.match(result.summary, /\| `lab-record-access` \| `1\.0\.0` \| `packs` \| `[0-9a-f]{64}` \|/);
  // An edited pack file no longer matches its manifest digests (the packs-v2 load check): refused before any request.
  const checks = join(workspace, 'app/packs/lab-record-access/checks.json'), original = await readFile(checks, 'utf8');
  try {
    await writeFile(checks, original.replace('lab record access pack', 'lab record access pack (edited)'));
    const edited = await runAction({ ...base(), 'pack-lock': 'app/scopehaven.lock' }, { workspace, runnerTemp, env });
    assert.equal(edited.steps.prepare.outcome, 'failure');
    assert.match(log(edited), /pack lock refused \(pack-digest-mismatch\); nothing was sent/);
    assert.equal(edited.steps.assess.outcome, 'skipped');
  } finally { await writeFile(checks, original); }
});

test('pack-updates report and off with every CI input on: signing, the ledger, its baseline and the pinned packs are unchanged; report only adds pack-status.json', async () => {
  const ledger = await newLedger('pack-updates');
  const inputs = { ...base(), ...ciInputs(ledger), 'baseline-from-ledger': 'true', 'pack-lock': 'app/scopehaven.lock' };
  const lockId = JSON.parse(await readFile(join(workspace, 'app/scopehaven.lock'), 'utf8')).lockId;
  const report = await runAction({ ...inputs, 'pack-updates': 'report' }, { workspace, runnerTemp, env });
  assert.equal(report.exitCode, 0, log(report));
  assert.equal(await realpath(report.steps.prepare.outputs.profile), await realpath(profileFile), 'report never changes the assessed profile');
  assert.deepEqual([report.steps.prepare.outputs['pack-lock-id'], report.steps.prepare.outputs['baseline-source']], [lockId, 'ledger-none']);
  assert.deepEqual([report.steps.ci.outputs['ci-state'], report.steps.ci.outputs['ledger-index']], ['ok', '0']);
  const out = join(report.steps.prepare.outputs.work, 'export');
  const status = JSON.parse(await readFile(join(out, 'pack-status.json'), 'utf8'));
  assert.deepEqual(status.packs.map(p => [p.as, p.name, p.pinned, p.state]), [['LR', 'lab-record-access', '1.0.0', 'local']]);
  assert.ok(!(await readdir(out)).includes('pack-pull.json'), 'report pulls nothing');
  assert.match(report.summary, /### Check packs[\s\S]*\| `LR` \| `lab-record-access` \| `1\.0\.0` \| none \| the operator's own pack \|/);
  assert.match(report.summary, /\*\*Pinned packs:\*\* lock `[0-9a-f]{64}` verified before any request/);
  const off = await runAction({ ...inputs, 'pack-updates': 'off' }, { workspace, runnerTemp, env });
  assert.equal(off.exitCode, 0, log(off));
  assert.deepEqual([off.steps.prepare.outputs['pack-lock-id'], off.steps.prepare.outputs['baseline-source']], [lockId, 'ledger']);
  assert.deepEqual([off.steps.ci.outputs['ci-state'], off.steps.ci.outputs['ledger-index']], ['ok', '1']);
  const offFiles = await readdir(join(off.steps.prepare.outputs.work, 'export'));
  assert.ok(!offFiles.includes('pack-status.json') && !offFiles.includes('pack-pull.json'), 'off reads no pack status');
  assert.doesNotMatch(off.summary, /### Check packs/);
});

test('pack-updates pull refused through action.yml: a pin a major version behind, or a pack that no longer ships, stops the prepare step with exit 2 and its code, before any request', async () => {
  const profile = JSON.parse(await readFile(profileFile, 'utf8'));
  for (const [state, ref] of [['major', { name: 'tenant-isolation', version: '0.9.0', as: 'TI', params: {} }], ['missing', { name: 'no-longer-shipped', version: '1.0.0', as: 'NS', params: {} }]]) {
    const dir = await privateDir(join(workspace, `pull-${state}`));
    const changed = structuredClone(profile);
    changed.targets[0].packs = [ref];
    changed.targets[0].checks = changed.targets[0].checks.filter(check => !check.pack).concat({ pack: ref.as });
    await writeFile(join(dir, 'targets.json'), JSON.stringify(changed));
    const result = await runAction({ ...base(), profile: `pull-${state}/targets.json`, 'pack-updates': 'pull' }, { workspace, runnerTemp, env });
    assert.equal(result.steps.prepare.outcome, 'failure', state);
    assert.equal(result.exitCode, 2, state);
    assert.match(log(result), new RegExp(`::error::Scopehaven action: pack-updates pull refused \\(pack-pull-${state}\\); nothing was sent`), state);
    assert.deepEqual([result.steps.wait.outcome, result.steps.assess.outcome, result.steps.ci.outcome], ['skipped', 'skipped', 'skipped'], `${state}: nothing was sent`);
    assert.equal(result.steps.prepare.outputs.work, undefined, `${state}: no work output`);
    assert.equal(result.outputs['run-id'] ?? '', '', state);
  }
});

test('sign on: every export is a verified DSSE envelope, the public key is in the artifact, and both verifiers accept run.json', async () => {
  const result = await runAction({ ...base(), ...ciInputs() }, { workspace, runnerTemp, env });
  assert.equal(result.exitCode, 0, log(result));
  assert.equal(result.steps.ci.outputs['ci-state'], 'ok');
  const out = join(result.steps.prepare.outputs.work, 'export'), files = await readdir(out);
  for (const name of ['run.json', 'report.html', 'scopehaven.sarif']) assert.ok(files.includes(`${name}.dsse.json`), name);
  assert.ok(files.includes('scopehaven-signing-key.pub.pem'));
  assert.ok(!files.some(name => name.endsWith('signing-key.pem') && !name.endsWith('.pub.pem')), 'no private key in the artifact');
  const evidence = JSON.parse(await readFile(join(out, 'ci-evidence.json'), 'utf8'));
  assert.equal(evidence.signing.state, 'verified');
  assert.equal(evidence.signing.envelopes.length, 3);
  const args = ['--key', join(out, 'scopehaven-signing-key.pub.pem'), '--envelope', join(out, 'run.json.dsse.json'), '--dir', out];
  await must(run(node, [join(root, 'integrations/attest/cli.mjs'), 'verify', ...args], { env }), 'node attest verify');
  await must(run('python3', ['-I', join(root, 'integrations/attest/verify_envelope.py'), ...args], { env: { PATH: '/usr/bin:/bin' } }), 'python attest verify');
  assert.match(result.summary, /\*\*Signed exports:\*\* verified; key id `[0-9a-f]{64}`; 3 of 3 envelopes verified/);
  // No private key bytes anywhere in the logs, summary or artifact.
  const secret = (await readFile(join(keys.evidence, 'scopehaven-signing-key.pem'), 'utf8')).split('\n')[1];
  for (const text of [result.summary, log(result), ...await Promise.all(files.map(name => readFile(join(out, name), 'utf8')))]) assert.ok(!text.includes(secret));
});

test('sign on with an unsafe key: the exports are not signed and the job fails with a named reason (exit 2)', async () => {
  const unsafe = await privateDir(join(scratch, 'keys/unsafe'));
  await must(run(node, [join(root, 'integrations/attest/cli.mjs'), 'keygen', '--dir', unsafe], { env }), 'keygen');
  await chmod(join(unsafe, 'scopehaven-signing-key.pem'), 0o644);
  const result = await runAction({ ...base(), sign: 'true', 'signing-key-dir': unsafe }, { workspace, runnerTemp, env });
  assert.equal(result.steps.ci.outputs['ci-state'], 'failed');
  assert.match(result.steps.ci.outputs['ci-reason'], /^signed-export-unverified:run\.json$/);
  assert.equal(result.exitCode, 2);
  assert.match(log(result), /::error::Scopehaven CI evidence: fail \(signed-export-unverified:run\.json\)/);
});

test('ledger and baseline-from-ledger on: each release appends one signed run, the regressed release fails, and a tampered ledger is refused', async () => {
  const ledger = await newLedger('releases');
  const inputs = { ...base(), ...ciInputs(ledger), 'baseline-from-ledger': 'true', 'pack-lock': 'app/scopehaven.lock' };
  // Release 1: an empty ledger, so no baseline yet; assessed, signed and appended as entry 0.
  const first = await runAction(inputs, { workspace, runnerTemp, env });
  assert.equal(first.exitCode, 0, log(first));
  assert.equal(first.steps.prepare.outputs['baseline-source'], 'ledger-none');
  assert.equal(first.outputs['gate-verdict'], 'not-requested');
  assert.deepEqual([first.steps.ci.outputs['ci-state'], first.steps.ci.outputs['ledger-index'], first.steps.ci.outputs['ledger-size']], ['ok', '0', '1']);
  assert.ok((await readdir(ledger.runFiles)).includes(`${first.outputs['run-id']}.json`));
  assert.match(first.summary, /\*\*Baseline from the ledger:\*\* none \(`ledger-empty`\)/);
  // Release 2: the lab's existing regressed build. The baseline is release 1's signed run from the ledger; the gate fails the job
  // on the regression (exit 1), and the run is still appended (entry 1).
  lab.setBuild('baseline');
  let second;
  try { second = await runAction(inputs, { workspace, runnerTemp, env }); } finally { lab.setBuild('repaired'); }
  assert.equal(second.steps.prepare.outputs['baseline-source'], 'ledger');
  const chosen = JSON.parse(await readFile(join(second.steps.prepare.outputs.work, 'export/ledger-baseline.json'), 'utf8'));
  assert.deepEqual([chosen.state, chosen.entry, chosen.runId], ['selected', 0, first.outputs['run-id']]);
  assert.equal(second.outputs['gate-verdict'], 'assessment-failed');
  const gate = JSON.parse(await readFile(join(second.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8'));
  assert.equal(gate.comparison.compatibility, 'compatible');
  assert.equal(gate.comparison.labels.regression, 2);
  assert.deepEqual([second.steps.ci.outputs['ci-state'], second.steps.ci.outputs['ledger-index'], second.steps.ci.outputs['ledger-size']], ['ok', '1', '2']);
  assert.equal(second.exitCode, 1);
  assert.match(log(second), /::error::Scopehaven decision: fail/);
  // Both verifiers accept the ledger with the kept run files.
  const ledgerPub = join(keys.ledger, 'scopehaven-signing-key.pub.pem'), evidencePub = join(keys.evidence, 'scopehaven-signing-key.pub.pem');
  const verifyArgs = ['--ledger', ledger.dir, '--key', ledgerPub, '--evidence-key', evidencePub, '--run-files', ledger.runFiles];
  const nodeVerify = JSON.parse((await must(run(node, [join(root, 'integrations/ledger/cli.mjs'), 'verify', ...verifyArgs], { env }), 'ledger verify')).stdout);
  assert.deepEqual([nodeVerify.verdict, nodeVerify.size, nodeVerify.verdictsCheckedAgainstRunFiles], ['verified', 2, 2]);
  const pythonVerify = JSON.parse((await must(run('python3', ['-I', join(root, 'integrations/ledger/verify_ledger.py'), 'log', '--key', ledgerPub, '--ledger', ledger.dir, '--evidence-key', evidencePub, '--run-files', ledger.runFiles], { env: { PATH: '/usr/bin:/bin' } }), 'python ledger verify')).stdout);
  assert.deepEqual([pythonVerify.verdict, pythonVerify.size], ['verified', 2]);
  // A line appended to entries.jsonl by someone else: the ledger baseline is refused before any request, and an append without
  // the ledger baseline is refused by the ledger's own writer (exit 2, named reason).
  await appendFile(join(ledger.dir, 'entries.jsonl'), '{"index":2}\n');
  const refused = await runAction(inputs, { workspace, runnerTemp, env });
  assert.equal(refused.steps.prepare.outcome, 'failure');
  assert.match(log(refused), /ledger baseline refused \(ledger-unverified\); nothing was sent/);
  const { 'baseline-from-ledger': _, ...withoutBaseline } = inputs;
  const append = await runAction(withoutBaseline, { workspace, runnerTemp, env });
  assert.deepEqual([append.steps.ci.outputs['ci-state'], append.steps.ci.outputs['ci-reason']], ['failed', 'ledger-append-refused']);
  assert.equal(append.exitCode, 2);
  assert.match(log(append), /::error::Scopehaven CI evidence: fail \(ledger-append-refused\)/);
  assert.ok(!(await readdir(ledger.runFiles)).includes(`${append.outputs['run-id']}.json`), 'a refused append removes the run file it kept');
});
