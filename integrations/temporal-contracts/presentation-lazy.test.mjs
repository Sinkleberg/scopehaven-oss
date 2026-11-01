// Real owned loopback runs and isolated source copies only. No live providers,
// hosted databases, model calls, or edits to the executing/shared source tree.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, realpath, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runRefundAssessment } from './runner.mjs';
import { escape, renderReport } from '../../src/report.mjs';
import { renderSarif } from '../../src/sarif.mjs';

const exec = promisify(execFile);
async function copiedApplication(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scopehaven-refund-presentation-lazy-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const application = join(root, 'copied application');
  await cp(fileURLToPath(new URL('../../src/', import.meta.url)), join(application, 'src'), { recursive: true });
  await cp(fileURLToPath(new URL('../', import.meta.url)), join(application, 'integrations'), { recursive: true });
  await cp(fileURLToPath(new URL('../../package.json', import.meta.url)), join(application, 'package.json'));
  return { root, application };
}
async function child(application, program) {
  const registry = pathToFileURL(join(application, 'src', 'registry.mjs')).href;
  const gate = pathToFileURL(join(application, 'integrations', 'regression-gate', 'gate.mjs')).href;
  const script = `import assert from 'node:assert/strict';
    import { appendFile } from 'node:fs/promises';
    import { createRegistry } from ${JSON.stringify(registry)};
    import { runGate } from ${JSON.stringify(gate)};
    ${program}`;
  const { stdout, stderr } = await exec(process.execPath, ['--input-type=module', '-e', script],
    { env: { PATH: '/usr/bin:/bin' }, timeout: 15000, maxBuffer: 262144 });
  assert.equal(stderr, '');
  return JSON.parse(stdout);
}

test('L1: real refund results render HTML and SARIF with scope and every row remediation', async () => {
  const run = await runRefundAssessment('refund-clean');
  assert.match(run.scopeLabel, /owned synthetic refund/i);
  assert.match(run.scopeLabel, /operator windows/i);
  assert.match(run.scopeLabel, /acceptance timing.*control/i);
  assert.match(run.scopeLabel, /no real provider or model/i);
  const html = renderReport(run), sarif = renderSarif(run);
  assert.ok(html.includes(escape(run.scopeLabel)));
  assert.ok(!html.includes('Evidence scope not supplied'));
  assert.equal(sarif.version, '2.1.0');
  const exported = sarif.runs[0];
  assert.equal(exported.properties.scope, run.scopeLabel);
  assert.equal(exported.results.length, run.results.length);
  const articles = html.match(/<article>.*?<\/article>/gs) ?? [];
  assert.equal(articles.length, run.results.length);
  for (const row of run.results) {
    const remediation = row.remediation;
    assert.ok(typeof remediation?.title === 'string' && remediation.title.trim(), row.id);
    assert.ok(typeof remediation.why === 'string' && remediation.why.trim(), row.id);
    assert.ok(Array.isArray(remediation.steps) && remediation.steps.length > 0 &&
      remediation.steps.every(step => typeof step === 'string' && step.trim()), row.id);
    const article = articles.find(value => value.includes(`<h2>${escape(row.id)} ·`));
    assert.ok(article, row.id);
    const rule = exported.tool.driver.rules.find(value => value.id === row.id);
    assert.ok(rule, row.id);
    for (const text of [remediation.title, remediation.why, ...remediation.steps]) {
      assert.ok(article.includes(escape(text)), `HTML remediation for ${row.id}`);
      assert.ok(rule.help.text.includes(text), `SARIF remediation for ${row.id}`);
    }
  }
});

test('L4: refund source changes block refund requests while a fresh registry and demo gate remain usable', { timeout: 20000 }, async t => {
  const { root, application } = await copiedApplication(t);
  const changed = join(application, 'integrations', 'temporal-contracts', 'binding.mjs');
  const output = await child(application, `
    const initial = createRegistry({env:{}}); await initial.ready;
    assert.equal((await initial.currentSuite('refund-clean')).sourceReady, true);
    await appendFile(${JSON.stringify(changed)}, '\\n// isolated refund source change\\n');
    const registry = createRegistry({env:{}});
    assert.equal(registry.has('demo-repaired'), true);
    const suite = await registry.currentSuite('demo-repaired');
    assert.ok(suite.checks.length > 0);
    const gate = await runGate({targetId:'demo-repaired',outputDirectory:${JSON.stringify(join(root, 'gate-output'))}}, {env:{}});
    assert.equal(gate.exitCode, 0, JSON.stringify(gate));
    await assert.rejects(registry.currentSuite('refund-clean'), {message:'refund-source-restart-required'});
    await assert.rejects(registry.run('refund-clean'), {message:'refund-source-restart-required'});
    process.stdout.write(JSON.stringify({demoGate:gate.outcome,refundBlocked:true}));`);
  assert.deepEqual(output, { demoGate: 'clean', refundBlocked: true });
});

test('L4: a missing refund runner at initial import leaves registry readiness and a non-refund gate usable', { timeout: 20000 }, async t => {
  const { root, application } = await copiedApplication(t);
  const runner = join(application, 'integrations', 'temporal-contracts', 'runner.mjs');
  await rename(runner, `${runner}.unavailable`);
  const output = await child(application, `
    const registry = createRegistry({env:{}});
    assert.equal(registry.has('demo-repaired'), true);
    assert.ok((await registry.currentSuite('demo-repaired')).checks.length > 0);
    const gate = await runGate({targetId:'demo-repaired',outputDirectory:${JSON.stringify(join(root, 'gate-output'))}}, {env:{}});
    assert.equal(gate.exitCode, 0, JSON.stringify(gate));
    const unavailable = error => error.code === 'ERR_MODULE_NOT_FOUND' && error.url === ${JSON.stringify(pathToFileURL(runner).href)};
    await assert.rejects(registry.currentSuite('refund-clean'), unavailable);
    await assert.rejects(registry.run('refund-clean'), unavailable);
    process.stdout.write(JSON.stringify({demoGate:gate.outcome,refundUnavailable:true}));`);
  assert.deepEqual(output, { demoGate: 'clean', refundUnavailable: true });
});


test('L1/L4: lazy refund definitions and a real dashboard assessment render without HTTP 500', async t => {
  const { startServer } = await import('../../src/server.mjs');
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-refund-dashboard-'));
  const app = await startServer({port:0,dataDir:join(root,'store'),env:{}});
  t.after(async()=>{await app.close();await rm(root,{recursive:true,force:true});});
  const headers={Authorization:`Bearer ${app.accessToken}`};
  const definitions=await fetch(`${app.origin}/api/suite/export.json?targetId=refund-clean`,{headers});
  assert.equal(definitions.status,200);assert.equal((await definitions.json()).targetId,'refund-clean');
  const response=await fetch(`${app.origin}/api/runs`,{method:'POST',headers:{...headers,'Content-Type':'application/json','X-Scopehaven-Request':'1'},body:JSON.stringify({targetId:'refund-clean'})});
  assert.equal(response.status,201);const run=await response.json();
  const report=await fetch(`${app.origin}/api/runs/${run.id}/report.html`,{headers});
  assert.equal(report.status,200);const html=await report.text();
  assert.ok(html.includes(run.scopeLabel));assert.ok(html.includes('Review refund evidence'));
});
