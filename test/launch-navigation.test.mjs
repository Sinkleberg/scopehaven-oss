import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';

// A link on the private launch page (a file:// document) arrives as a cross-site
// top-level navigation. Only that navigation to an HTML shell may pass; everything
// else that a browser labels cross-site stays refused.
const NAVIGATE = { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1' };

function raw(origin, path, { method = 'GET', headers = {}, payload } = {}) {
  return new Promise((resolve, reject) => {
    const buffer = payload === undefined ? undefined : Buffer.from(payload);
    const req = request(`${origin}${path}`, { method, agent: false, headers: { ...headers, ...(buffer ? { 'Content-Length': buffer.length } : {}) } }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('Owned local test request timed out.'))); req.end(buffer);
  });
}

async function workbench(t) {
  const dataDir = await mkdtemp(join(tmpdir(), 'scopehaven-launch-'));
  const app = await startServer({ port: 0, dataDir, env: {} });
  t.after(async () => { await app.close(); await rm(dataDir, { recursive: true, force: true }); });
  return app;
}

test('a cross-site top-level navigation from the launch page opens the workbench and intro shells', async t => {
  const app = await workbench(t);
  for (const path of ['/', '/index.html', '/intro/', '/intro/index.html']) {
    const response = await raw(app.origin, path, { headers: NAVIGATE });
    assert.equal(response.status, 200, path);
    assert.match(response.headers['content-type'], /^text\/html/);
    assert.equal(response.text.includes(app.accessToken), false);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
  }
});

test('every other cross-site request stays refused', async t => {
  const app = await workbench(t);
  const auth = { Authorization: `Bearer ${app.accessToken}` };
  const refused = [
    ['/', { 'Sec-Fetch-Site': 'cross-site' }],
    ['/', { ...NAVIGATE, 'Sec-Fetch-Mode': 'no-cors' }],
    ['/', { ...NAVIGATE, 'Sec-Fetch-Dest': 'iframe' }],
    ['/', { ...NAVIGATE, 'Sec-Fetch-Dest': 'script' }],
    ['/', { ...NAVIGATE, Origin: 'https://attacker.invalid' }],
    ['/workbench-host.js', NAVIGATE],
    ['/access.css', NAVIGATE],
    ['/intro/intro.js', NAVIGATE],
    ['/api/access-info', NAVIGATE],
    ['/api/bootstrap', { ...auth, ...NAVIGATE }],
    ['/api/suite/export.json', { ...auth, ...NAVIGATE }],
  ];
  for (const [path, headers] of refused) {
    const response = await raw(app.origin, path, { headers });
    assert.equal(response.status, 403, `${path} ${JSON.stringify(headers)}`);
    assert.equal(JSON.parse(response.text).code, 'cross-origin-denied');
  }
  const post = await raw(app.origin, '/api/runs', { method: 'POST', headers: { ...auth, ...NAVIGATE, 'X-Scopehaven-Request': '1', 'Content-Type': 'application/json' }, payload: '{}' });
  assert.equal(post.status, 403);
});

test('same-origin and direct navigations keep working unchanged', async t => {
  const app = await workbench(t);
  for (const site of ['same-origin', 'none']) {
    const response = await raw(app.origin, '/', { headers: { 'Sec-Fetch-Site': site, 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } });
    assert.equal(response.status, 200, site);
  }
  assert.equal((await raw(app.origin, '/')).status, 200);
});
