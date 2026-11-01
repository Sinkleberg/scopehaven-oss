import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { makeLabProfile } from './http-lab.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { renderReport } from '../src/report.mjs';

const child = fork(fileURLToPath(new URL('http-lab.mjs', import.meta.url)), [], { env: { ...process.env, SCOPEHAVEN_LAB_IPC: '1' }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
const waitFor = type => new Promise((resolve, reject) => {
  const timer = setTimeout(() => { cleanup(); reject(new Error('Owned lab did not respond in time.')); }, 5000);
  const onMessage = message => { if (message?.type === type) { cleanup(); resolve(message); } };
  const onExit = () => { cleanup(); reject(new Error('Owned lab exited before becoming ready.')); };
  const cleanup = () => { clearTimeout(timer); child.off('message', onMessage); child.off('exit', onExit); };
  child.on('message', onMessage); child.once('exit', onExit);
});
try {
  const ready = await waitFor('ready');
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: ready.memberToken };
  const directory = fileURLToPath(new URL('../artifacts/http-contract-demo/', import.meta.url));
  const store = createStore(directory);
  await store.ready;
  const baseline = await store.save(await runHttpAssessment(makeLabProfile(ready.origin, 'lab-baseline'), { env }));
  const changed = waitFor('build-ready'); child.send({ type: 'build', build: 'repaired' }); await changed;
  const candidate = await store.save(await runHttpAssessment(makeLabProfile(ready.origin, 'lab-repaired'), { env }));
  const comparison = compareRuns(baseline, candidate);
  const serialized = JSON.stringify({ baseline, candidate, comparison });
  if (serialized.includes(ready.memberToken) || serialized.includes('SYNTHETIC_PRIVATE_RESPONSE_DO_NOT_STORE')) throw new Error('Response-content persistence regression.');
  if (baseline.counts.fail !== 2 || candidate.counts.pass !== 6 || candidate.counts.inconclusive !== 1 || comparison.summary.fixed !== 1) throw new Error('Unexpected connector demonstration result.');
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'comparison.json'), JSON.stringify(comparison, null, 2));
  await writeFile(resolve(directory, 'candidate-report.html'), renderReport(candidate));
  console.log(JSON.stringify({ target: 'Separate owned HTTP process', baseline: { id: baseline.id, counts: baseline.counts }, candidate: { id: candidate.id, counts: candidate.counts }, comparison: comparison.summary,
    interpretation: 'One HTTP response contract restored; one backend requirement remains unverified. No production/model/provider calls.', evidenceDirectory: directory }, null, 2));
} finally {
  if (child.exitCode === null) { const exited = once(child, 'exit'); child.kill('SIGTERM'); await exited; }
}
