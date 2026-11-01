// The owned refund agent demo end to end: run the pack against the vulnerable build (three planted defects
// fail from the ledger), swap in the repaired build on the same port, rerun against the first run, and write
// both runs, both reports, the pack and its authorization record into one directory. Loopback only.
import { createServer } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runPaymentsPack, comparePaymentsRuns } from '../pack.mjs';
import { writeRun, summarize } from '../output.mjs';
import { startRefundAgentApp, demoPackConfig, demoAuthorization, DEMO_TOKENS } from './refund-agent-app.mjs';

// Two loopback ports the OS has free right now (the demo is a one-off, not a suite under load).
async function freePorts(count) {
  const servers = [];
  try {
    for (let i = 0; i < count; i++) {
      const s = createServer();
      await new Promise((resolve, reject) => { s.once('error', reject); s.listen({ port: 0, host: '127.0.0.1', exclusive: true }, resolve); });
      servers.push(s);
    }
    return servers.map(s => s.address().port);
  } finally { await Promise.all(servers.map(s => new Promise(resolve => s.close(resolve)))); }
}

export async function runDemo(directory, { now = new Date() } = {}) {
  const [appPort, payPort] = await freePorts(2);
  const config = demoPackConfig({ appPort, payPort }), record = demoAuthorization(config, { now });
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'refund-agent.pack.json'), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(directory, 'refund-agent.authorization.json'), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  const runBuild = async variant => {
    const app = await startRefundAgentApp({ port: appPort, payPort, variant });
    try { return await runPaymentsPack(config, { record, env: DEMO_TOKENS, now, build: `refund-agent-${variant}` }); } finally { await app.stop(); }
  };
  const before = await runBuild('vulnerable');
  const beforeFiles = await writeRun(join(directory, 'before'), before);
  const after = await runBuild('repaired');
  const comparison = comparePaymentsRuns(before, after);
  const afterFiles = await writeRun(join(directory, 'after'), after, comparison);
  return { before: summarize(before, beforeFiles), after: summarize(after, afterFiles, comparison), comparison: { verdict: comparison.verdict, reason: comparison.reason } };
}
