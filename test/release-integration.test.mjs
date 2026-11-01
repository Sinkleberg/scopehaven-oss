import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, stat, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { startServer } from '../src/server.mjs';
import { exportRun } from '../src/export-cli.mjs';
import { loadProfiles } from '../src/registry.mjs';

// Owned loopback fixture only. No application/provider credentials or network
// destinations beyond ephemeral127.0.0.1. Files stay in fresh private temp dirs.
test('integrated saved-evidence gate, static intro and private export preserve boundaries', async t => {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-release-'));
  const app = await startServer({ port: 0, dataDir: join(root, 'store'), env: {} });
  t.after(async () => { await app.close(); await rm(root, { recursive: true, force: true }); });
  const auth = { Authorization: `Bearer ${app.accessToken}` };
  const run = async targetId => {
    const response = await fetch(`${app.origin}/api/runs`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1' }, body: JSON.stringify({ targetId }) });
    assert.equal(response.status, 201); return response.json();
  };
  const baseline = await run('demo-vulnerable'), candidate = await run('demo-repaired');
  const gateUrl = `${app.origin}/api/runs/${candidate.id}/gate?baseline=${baseline.id}`;
  assert.equal((await fetch(gateUrl)).status, 401);
  const summary = await (await fetch(gateUrl, { headers: auth })).json();
  assert.equal(summary.exitCode, 0); assert.equal(summary.comparison.summary.fixed, 26);
  assert.equal(summary.evaluationMode, 'saved-evidence'); assert.equal(summary.assessmentExecuted, false); assert.equal(summary.scheduled, false);
  assert.equal((await (await fetch(`${app.origin}/api/runs/${baseline.id}/gate`, { headers: auth })).json()).exitCode, 1);
  assert.equal((await app.store.historyPage()).total, 2);

  const intro = await fetch(`${app.origin}/intro/`), html = await intro.text();
  assert.equal(intro.status, 200); assert.match(intro.headers.get('content-security-policy'), /connect-src 'none'/);
  assert.equal([...html.matchAll(/href="\/"/g)].length, 3);
  assert.doesNotMatch(html, /#access=|127\.0\.0\.1:4317|\/api\//);
  for (const asset of ['styles.css', 'intro.js', 'particle-scene.js']) assert.equal((await fetch(`${app.origin}/intro/${asset}`)).status, 200);
  assert.equal((await fetch(`${app.origin}/intro/INTEGRATION.md`)).status, 404);
  assert.equal((await fetch(`${app.origin}/data/local-access.html`)).status, 404);

  const out = join(root, 'exports'); await mkdir(out, { mode: 0o700 });
  for (const format of ['json', 'html']) {
    const path = join(out, `evidence.${format}`);
    const receipt = await exportRun({ runId: candidate.id, format, outputFile: path, dataDir: join(root, 'store') });
    const bytes = await readFile(path);
    assert.equal(receipt.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal(bytes.includes(Buffer.from(app.accessToken)), false);
    if (format === 'json') assert.equal(JSON.parse(bytes).id, candidate.id);
    else assert.match(bytes.toString(), /Scopehaven/);
    await assert.rejects(exportRun({ runId: baseline.id, format, outputFile: path, dataDir: join(root, 'store') }));
    assert.deepEqual(await readFile(path), bytes);
  }
  const alias = join(root, 'alias'); await symlink(out, alias);
  await assert.rejects(exportRun({ runId: candidate.id, format: 'json', outputFile: join(alias, 'blocked.json'), dataDir: join(root, 'store') }));
});

test('configured profiles reject invalid UTF-8, symlinks and oversized files before assessment', async t => {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-profile-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'input.json'), alias = join(root, 'alias.json');
  await writeFile(path, Buffer.concat([Buffer.from('{"schemaVersion":1,"targets":[],"extra":"'), Buffer.from([0xff]), Buffer.from('"}')]));
  await assert.rejects(loadProfiles(path), /UTF-8/);
  await writeFile(path, '{"schemaVersion":1,"targets":[]}'); await symlink(path, alias);
  await assert.rejects(loadProfiles(alias));
  await writeFile(path, ' '.repeat(2097153)); await assert.rejects(loadProfiles(path), /2 MiB/);
});
