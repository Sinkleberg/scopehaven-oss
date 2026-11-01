#!/usr/bin/env node
// Local proof of the action's CI mode over 10 releases of an owned app. Laptop only: no GitHub runner, no workflow dispatch, no
// push, no network beyond 127.0.0.1. It builds a scratch git repository under $TMPDIR (outside the checkout) holding an owned
// app: ScopeHaven's own synthetic HTTP lab (examples/http-lab.mjs) at the build named in the repository's BUILD file, its
// profile and authorization written at start the way `./scopehaven lab` writes them, and an operator pack locked with
// `scopehaven pack lock`. It tags v1 to v10. Release v6 sets BUILD to the lab's existing `baseline` build (the foreign-record
// regression the repository's own action workflow already uses; no new defect is written) and v7 goes back to `repaired`.
// For each release it checks the tag out, starts the app, and runs action.yml's own run steps in order (harness.mjs) with
// sign, ledger-dir, baseline-from-ledger, pack-lock and fail-on fail. Keys, the ledger and the run files stay in the scratch
// folder. Afterwards it verifies the ledger with integrations/ledger/cli.mjs verify and with python3 -I verify_ledger.py log,
// and writes CI-PROOF-RECEIPT.json beside this file (or --receipt ABS).
//   node integrations/github-action/ci-proof.mjs [--receipt ABS_FILE] [--keep]
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawn as spawnChild } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { here, run, runAction } from './harness.mjs';

const root = resolve(here, '../..');
const node = process.execPath;
const RELEASES = 10, REGRESSED = 6;
const buildOf = release => release === REGRESSED ? 'baseline' : 'repaired';
const git = (cwd, ...args) => run('git', ['-c', 'user.name=ci-proof', '-c', 'user.email=ci-proof@localhost.invalid', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], { cwd });
const must = async (promise, what) => { const result = await promise; if (result.code !== 0) throw new Error(`${what} failed (exit ${result.code}): ${result.stderr.slice(0, 400)}`); return result; };
const json = value => `${JSON.stringify(value, null, 2)}\n`;

// The operator pack (from: packs in the app repository): two checks templated from the lab profile's OWN-RECORD and
// FOREIGN-STATUS. Sealed with `scopehaven pack seal`, which writes the file digests into the manifest.
export const PACK = {
  'manifest.json': { schema: 'scopehaven-pack/1', name: 'lab-record-access', version: '1.0.0', behaviour: 'A member reads their own record, and a request for another tenant\'s record is refused.',
    derivedFrom: ['owned HTTP lab profile: OWN-RECORD and FOREIGN-STATUS (examples/http-lab.mjs makeLabProfile)'],
    parameters: { actor: { type: 'actor', description: 'The member actor.' }, ownPath: { type: 'path', description: 'The route of the actor\'s own record (GET).' },
      foreignPath: { type: 'path', description: 'The route of another tenant\'s record (GET).' }, tenantPointer: { type: 'pointer', default: '/record/tenant', description: 'Where the own record names its tenant.' },
      refusalStatuses: { type: 'statuses', default: [403, 404], description: 'The statuses that count as a refusal.' } },
    constraints: [['different', 'ownPath', 'foreignPath']], regulation: null, files: { 'checks.json': '0'.repeat(64), 'cases.json': '0'.repeat(64) } },
  'checks.json': { schema: 'scopehaven-pack-checks/1', checks: [
    { id: '{{as}}-OWN', title: '{{actor}} reads their own record ({{as}}, lab record access pack)', category: 'Allowed use', severity: 'control', actorId: '{{actor}}', method: 'GET', path: '{{ownPath}}', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '{{tenantPointer}}', expected: '{{actor.tenantId}}' }] },
    { id: '{{as}}-FOREIGN', title: '{{actor}} is refused another tenant\'s record ({{as}}, lab record access pack)', category: 'Local application contracts', severity: 'high', actorId: '{{actor}}', method: 'GET', path: '{{foreignPath}}', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.in', expected: '{{refusalStatuses}}' }] }],
  requiredControlIds: ['{{as}}-OWN'] },
  'cases.json': { schema: 'scopehaven-pack-cases/1',
    target: { id: 'pack-self-test', name: 'Pack self-test target (synthetic, never contacted)', applicationId: 'pack-self-test', origin: 'http://127.0.0.1:8080', buildLabel: 'self-test', contextId: 'synthetic-records-v1',
      actors: { member: { principalId: 'member-a', tenantId: 'aster', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_PACK_MEMBER', identityValue: 'member-a' } }, checks: [] },
    cases: [{ id: 'defaults', as: 'LR', params: { actor: 'member', ownPath: '/records/own', foreignPath: '/records/foreign' }, expect: { 'LR-OWN': 'proven', 'LR-FOREIGN': 'proven' } }] },
};

// The owned app: the lab at ./BUILD on a loopback port (OS-assigned on the first start, then reused), writing its profile (the lab profile without BACKEND-UNVERIFIED,
// a backend-required row a response-only run keeps inconclusive, plus the pack) and the lab's authorization record beside the
// lock, and its synthetic member token into the runtime folder outside the repository. It prints one JSON line when ready.
const APP = `// Owned app under test for the Scopehaven CI proof: the synthetic HTTP lab at the build named in ./BUILD.
import { readFileSync, writeFileSync } from 'node:fs';
const { createHttpLab, makeLabProfile, makeLabAuthorization } = await import(process.env.LAB_MODULE);
const build = readFileSync(new URL('./BUILD', import.meta.url), 'utf8').trim();
const version = readFileSync(new URL('./VERSION', import.meta.url), 'utf8').trim();
const lab = await createHttpLab({ port: Number(process.env.APP_PORT), build });
const profile = makeLabProfile(lab.origin, 'release-' + version);
profile.checks = profile.checks.filter(check => check.id !== 'BACKEND-UNVERIFIED');
profile.checks.push({ pack: 'LR' });
profile.packs = [{ name: 'lab-record-access', version: '1.0.0', as: 'LR', from: 'packs', params: { actor: 'member', ownPath: '/records/own', foreignPath: '/records/foreign' } }];
writeFileSync(new URL('./scopehaven/targets.json', import.meta.url), JSON.stringify({ schemaVersion: 1, targets: [profile] }, null, 2), { mode: 0o600 });
writeFileSync(new URL('./scopehaven/authorization.json', import.meta.url), JSON.stringify(makeLabAuthorization(lab.origin), null, 2), { mode: 0o600 });
writeFileSync(process.env.APP_RUNTIME + '/member-token', lab.memberToken, { mode: 0o600 });
console.log(JSON.stringify({ ready: true, origin: lab.origin, build, version }));
for (const event of ['SIGINT', 'SIGTERM']) process.on(event, async () => { await lab.close(); process.exit(0); });
`;

function startApp(repo, env) {
  return new Promise((done, fail) => {
    const child = spawnChild(node, ['app.mjs'], { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    const timer = setTimeout(() => { child.kill('SIGTERM'); fail(new Error(`the app did not start: ${err.slice(0, 400)}`)); }, 30000);
    child.stderr.on('data', chunk => { err += chunk; });
    child.stdout.on('data', chunk => {
      out += chunk;
      const line = out.split('\n').find(l => l.startsWith('{'));
      if (line) { clearTimeout(timer); done({ child, ready: JSON.parse(line) }); }
    });
    child.once('exit', code => { clearTimeout(timer); fail(new Error(`the app exited (${code}): ${err.slice(0, 400)}`)); });
  });
}
const stopApp = child => new Promise(done => { if (child.exitCode !== null) return done(); child.removeAllListeners('exit'); child.once('exit', () => done()); child.kill('SIGTERM'); });

export async function proof({ receipt = join(here, 'CI-PROOF-RECEIPT.json'), keep = false } = {}) {
  const scratch = await mkdtemp(join(process.env.TMPDIR || tmpdir(), 'scopehaven-ci-proof-'));
  await chmod(scratch, 0o700);
  const dirs = Object.fromEntries(['keys', 'keys/evidence', 'keys/ledger', 'ledger', 'run-files', 'runtime', 'runner-temp', 'home'].map(name => [name, join(scratch, name)]));
  for (const dir of Object.values(dirs)) await mkdir(dir, { mode: 0o700 });
  const repo = join(scratch, 'owned-app');
  const env = { PATH: `${dirname(node)}:/usr/bin:/bin`, HOME: dirs.home, TMPDIR: scratch, SCOPEHAVEN_NODE: node, LANG: 'C' };
  try {
    // Keys (attest keygen) and the operator's ledger (cli.mjs init); both stay in the scratch folder.
    for (const which of ['evidence', 'ledger']) await must(run(node, [join(root, 'integrations/attest/cli.mjs'), 'keygen', '--dir', dirs[`keys/${which}`]], { env }), `keygen ${which}`);
    await must(run(node, [join(root, 'integrations/ledger/cli.mjs'), 'init', '--ledger', dirs.ledger], { env }), 'ledger init');
    // The owned app repository with its pack, sealed and locked.
    await mkdir(join(repo, 'scopehaven/packs/lab-record-access'), { recursive: true, mode: 0o700 });
    await must(git(repo, 'init', '-q'), 'git init');
    await writeFile(join(repo, 'app.mjs'), APP);
    await writeFile(join(repo, '.gitignore'), 'scopehaven/targets.json\nscopehaven/authorization.json\n');
    await writeFile(join(repo, 'BUILD'), 'repaired\n');
    await writeFile(join(repo, 'VERSION'), 'v1\n');
    for (const [name, value] of Object.entries(PACK)) await writeFile(join(repo, 'scopehaven/packs/lab-record-access', name), json(value));
    await must(run(node, [join(root, 'integrations/packs-v2/cli.mjs'), 'seal', join(repo, 'scopehaven/packs/lab-record-access')], { env }), 'pack seal');
    // The first start takes an OS-assigned loopback port and writes the profile the lock is made from; every release reuses that
    // port, so the profile's origin (and the authorization record's) is the same across releases.
    const appEnv = { ...env, LAB_MODULE: pathToFileURL(join(root, 'examples/http-lab.mjs')).href, APP_PORT: '0', APP_RUNTIME: dirs.runtime };
    { const { child, ready } = await startApp(repo, appEnv); await stopApp(child); appEnv.APP_PORT = new URL(ready.origin).port; }
    await must(run(node, [join(root, 'integrations/packs-v2/cli.mjs'), 'lock', '--config', join(repo, 'scopehaven/targets.json')], { env }), 'pack lock');
    for (let release = 1; release <= RELEASES; release++) {
      await writeFile(join(repo, 'VERSION'), `v${release}\n`);
      await writeFile(join(repo, 'BUILD'), `${buildOf(release)}\n`);
      await must(git(repo, 'add', '-A'), 'git add');
      await must(git(repo, 'commit', '-q', '-m', `Release v${release} (${buildOf(release)} build)`), 'git commit');
      await must(git(repo, 'tag', `v${release}`), 'git tag');
    }
    const releases = [];
    for (let release = 1; release <= RELEASES; release++) {
      const tag = `v${release}`;
      await must(git(repo, 'checkout', '-q', tag), `checkout ${tag}`);
      const commit = (await must(git(repo, 'rev-parse', 'HEAD'), 'rev-parse')).stdout.trim();
      const { child, ready } = await startApp(repo, appEnv);
      let result;
      try {
        const token = (await readFile(join(dirs.runtime, 'member-token'), 'utf8')).trim();
        const runnerTemp = join(dirs['runner-temp'], tag);
        await mkdir(runnerTemp, { mode: 0o700 });
        result = await runAction({
          profile: 'scopehaven/targets.json', authorization: 'scopehaven/authorization.json', 'wait-url': `${ready.origin}/me`, 'fail-on': 'fail',
          sign: 'true', 'signing-key-dir': dirs['keys/evidence'],
          'ledger-dir': dirs.ledger, 'ledger-key-dir': dirs['keys/ledger'], 'ledger-run-files': dirs['run-files'], 'baseline-from-ledger': 'true',
          'pack-lock': 'scopehaven/scopehaven.lock',
        }, { workspace: repo, runnerTemp, env: { ...env, SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: token } });
      } finally { await stopApp(child); }
      const work = result.steps.prepare.outputs.work;
      const read = async name => { try { return JSON.parse(await readFile(join(work, 'export', name), 'utf8')); } catch { return null; } };
      const [evidence, base, lock, gate] = await Promise.all([read('ci-evidence.json'), read('ledger-baseline.json'), read('pack-lock.json'), read('gate-summary.json')]);
      const failStep = result.logs.find(l => l.name === 'Apply fail-on');
      releases.push({
        release: tag, commit, build: ready.build, runId: result.outputs['run-id'] || null,
        baseline: { source: result.steps.prepare.outputs['baseline-source'], state: base?.state ?? null, entry: base?.entry ?? null, runId: base?.runId ?? null, build: base?.build ?? null, reason: base?.reason ?? null },
        gate: { verdict: result.outputs['gate-verdict'], reasons: Array.isArray(gate?.reasons) ? gate.reasons : null, labels: gate?.comparison?.labels ?? null },
        statusCounts: result.outputs['status-counts'] ? JSON.parse(result.outputs['status-counts']) : null,
        decision: result.steps.summary?.outputs?.decision ?? null, decisionReason: result.steps.summary?.outputs?.['decision-reason'] ?? null,
        jobExit: result.exitCode, jobFailed: result.failed,
        failedStep: result.failed ? result.logs.find(l => l.code !== 0)?.name ?? null : null,
        failOnLine: (failStep?.stdout ?? '').trim().split('\n').at(-1) ?? null,
        ci: { state: result.steps.ci?.outputs?.['ci-state'] ?? null, reason: result.steps.ci?.outputs?.['ci-reason'] || null },
        signing: evidence?.signing ? { state: evidence.signing.state, keyid: evidence.signing.keyid ?? null, envelopesVerified: evidence.signing.envelopes.filter(e => e.verdict === 'verified').length, envelopes: evidence.signing.envelopes.length } : null,
        ledger: evidence?.ledger ? { state: evidence.ledger.state, index: evidence.ledger.index ?? null, size: evidence.ledger.size ?? null, verdict: evidence.ledger.verdict ?? null, rootHash: evidence.ledger.rootHash ?? null } : null,
        packLock: lock ? { lockId: lock.lockId, packs: lock.packs.map(p => `${p.name}@${p.version}${p.from ? ` from ${p.from}` : ''}`) } : null,
      });
      process.stderr.write(`${tag} ${ready.build}: job exit ${result.exitCode}, decision ${releases.at(-1).decision} (${releases.at(-1).decisionReason}), ledger ${releases.at(-1).ledger?.state} size ${releases.at(-1).ledger?.size}\n`);
    }
    // After 10 releases: both verifiers, over the whole ledger with the kept run files.
    const ledgerPub = join(dirs['keys/ledger'], 'scopehaven-signing-key.pub.pem'), evidencePub = join(dirs['keys/evidence'], 'scopehaven-signing-key.pub.pem');
    const nodeVerify = await run(node, [join(root, 'integrations/ledger/cli.mjs'), 'verify', '--ledger', dirs.ledger, '--key', ledgerPub, '--evidence-key', evidencePub, '--run-files', dirs['run-files']], { env });
    const pythonVerify = await run('python3', ['-I', join(root, 'integrations/ledger/verify_ledger.py'), 'log', '--key', ledgerPub, '--ledger', dirs.ledger, '--evidence-key', evidencePub, '--run-files', dirs['run-files']], { env: { PATH: '/usr/bin:/bin', LANG: 'C' } });
    const history = await run(node, [join(root, 'integrations/ledger/cli.mjs'), 'history', '--ledger', dirs.ledger, '--key', ledgerPub, '--evidence-key', evidencePub], { env });
    const parse = text => { try { return JSON.parse(text); } catch { return null; } };
    const nv = parse(nodeVerify.stdout), pv = parse(pythonVerify.stdout), hv = parse(history.stdout);
    const python = await run('python3', ['-I', '-c', 'import sys; print(sys.version.split()[0])'], { env: { PATH: '/usr/bin:/bin' } });
    const head = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
    const appended = releases.filter(r => r.ledger?.state === 'appended').length;
    const failed = releases.filter(r => r.jobFailed);
    const out = {
      schema: 'scopehaven-action-ci-proof/1',
      generatedAt: new Date().toISOString(),
      how: 'Local laptop run of action.yml\'s own run steps (harness.mjs) for each tagged release of a scratch owned-app repository under $TMPDIR; no GitHub runner, no workflow dispatch, no push; loopback only. uses: steps (setup-node, upload-artifact, upload-sarif) are not executed.',
      checkout: { head: head.stdout.trim() || null, dirtyFilesNotes: 'the CI-mode change was uncommitted in the worktree when this ran' },
      runtime: { node: process.version, python: python.stdout.trim() || null },
      app: 'ScopeHaven synthetic HTTP lab (examples/http-lab.mjs) at the build in the repository BUILD file; v6 uses the lab\'s existing baseline build (foreign record returned), every other release the repaired build. Profile: the lab profile without BACKEND-UNVERIFIED plus the operator pack lab-record-access@1.0.0 (from: packs), locked with scopehaven pack lock.',
      inputs: { 'fail-on': 'fail', sign: 'true', 'baseline-from-ledger': 'true', 'pack-lock': 'scopehaven/scopehaven.lock', 'ledger-dir': 'scratch', 'ledger-key-dir': 'scratch (a key separate from the evidence key)', 'ledger-run-files': 'scratch' },
      counts: { releases: releases.length, runsSaved: releases.filter(r => r.runId).length, signedRunsAppended: appended, jobsFailed: failed.length, jobsPassed: releases.length - failed.length,
        envelopesVerified: releases.reduce((n, r) => n + (r.signing?.envelopesVerified ?? 0), 0), envelopes: releases.reduce((n, r) => n + (r.signing?.envelopes ?? 0), 0) },
      failedReleases: failed.map(r => ({ release: r.release, build: r.build, jobExit: r.jobExit, decision: r.decision, reason: r.decisionReason, gateVerdict: r.gate.verdict, gateReasons: r.gate.reasons, labels: r.gate.labels, ledgerAppended: r.ledger?.state === 'appended' })),
      ledger: { size: nv?.size ?? null, covered: nv?.covered ?? null, unsignedTail: nv?.unsignedTail ?? null, checkpoints: nv?.checkpoints?.length ?? null, log: nv?.log ?? null, rootHash: nv?.checkpoints?.at(-1)?.rootHash ?? null, witness: nv?.witness ?? 'none' },
      verifiers: {
        node: { command: 'node integrations/ledger/cli.mjs verify --ledger L --key LEDGER_PUB --evidence-key EVIDENCE_PUB --run-files R', exit: nodeVerify.code, verdict: nv?.verdict ?? null, size: nv?.size ?? null, verdictsCheckedAgainstRunFiles: nv?.verdictsCheckedAgainstRunFiles ?? null, runs: nv?.runs ?? null },
        python: { command: 'python3 -I integrations/ledger/verify_ledger.py log --key LEDGER_PUB --ledger L --evidence-key EVIDENCE_PUB --run-files R', exit: pythonVerify.code, verdict: pv?.verdict ?? null, size: pv?.size ?? null, verdictsCheckedAgainstRunFiles: pv?.verdictsCheckedAgainstRunFiles ?? null, error: pv?.error ?? (pythonVerify.code === 0 ? null : pythonVerify.stderr.slice(0, 300)) },
      },
      history: hv?.segments ? { exit: history.code, segments: hv.segments.length, changes: hv.segments.flatMap(s => s.changes.map(c => ({ check: c.check, from: c.from, to: c.to, entry: c.entry, build: c.build }))) } : { exit: history.code, error: (history.stdout || history.stderr).slice(0, 300) },
      releases,
      shows: [
        'Each of the 10 releases ran the action\'s own steps with signing, the ledger, the pack lock and the ledger baseline on, and appended one signed run (entry index = release - 1).',
        'The release on the lab\'s existing regressed build failed the job against the previous release\'s run, taken from the ledger, while its signed run was still appended.',
        'After 10 releases the ledger verified with both the Node and the independent Python verifier, with every run file checked against its recorded verdicts.',
      ],
      doesNotShow: [
        'A GitHub-hosted or laptop-runner workflow run: GitHub expression evaluation, setup-node, the artifact upload and secrets reaching the step are not exercised here.',
        'Key custody on a runner: the keys sat in a scratch folder of the same user; on a real runner the application under test may be able to read them.',
        'Anything about the application beyond the owned synthetic lab, or that the checks or results are correct. Checkpoints are operator-signed only (witness none).',
      ],
    };
    await writeFile(receipt, json(out));
    return { receipt, scratch, out };
  } finally {
    if (!keep) await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2), options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--keep') options.keep = true;
    else if (args[i] === '--receipt' && args[i + 1]?.startsWith('/')) options.receipt = args[++i];
    else { console.error('Usage: ci-proof.mjs [--receipt ABS_FILE] [--keep]'); process.exit(2); }
  }
  const { receipt, scratch, out } = await proof(options);
  console.log(JSON.stringify({ receipt, scratch: options.keep ? scratch : 'removed', counts: out.counts, failedReleases: out.failedReleases.map(r => `${r.release}: ${r.reason}`), verifiers: { node: out.verifiers.node.exit, python: out.verifiers.python.exit } }, null, 2));
  process.exitCode = out.counts.signedRunsAppended === RELEASES && out.verifiers.node.exit === 0 && out.verifiers.python.exit === 0 && out.failedReleases.length >= 1 ? 0 : 1;
}
