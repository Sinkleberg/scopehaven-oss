// src/http-scope-text.mjs holds the HTTP connector's scope line and limitation
// wording. It must stay report text only: no imports, no verdict logic, outside
// the evaluator hash, and the validator must not depend on its sentences.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import * as text from '../src/http-scope-text.mjs';
import { FORWARDER_MARKER, validateHttpRunEvidence } from '../src/contracts.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';

const source = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');

test('the scope-text module imports nothing and only produces strings', async () => {
  const src = await source('http-scope-text.mjs');
  assert.doesNotMatch(src, /^\s*import\s|import\(/m, 'no imports');
  const declared = [{ id: 'db', type: 'sqlite-audit', settleMs: 1000 }, { id: 'tr', type: 'otel', settleMs: null }];
  for (const [name, value] of Object.entries(text)) {
    if (typeof value === 'string' || typeof value === 'number') continue; // text, or a number quoted in text
    assert.equal(typeof value, 'function', name);
    const out = name === 'observerScopeNote' ? value(declared) : value({ observed: true, forwarded: true, observersDeclared: true, declared });
    assert.ok(typeof out === 'string' || (Array.isArray(out) && out.every(s => typeof s === 'string')), `${name} returns text`);
  }
  assert.ok(text.FORWARDER_LIMITATION.includes(FORWARDER_MARKER), 'the forwarder sentence keeps the validator\'s marker phrase');
});

test('the scope text is outside the evaluator hash and no verdict module reads it', async () => {
  const connector = await source('http-connector.mjs');
  const hashed = /const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(connector)[1];
  assert.doesNotMatch(hashed, /http-scope-text/);
  for (const name of ['contracts.mjs', 'http-effects.mjs', 'effect-events.mjs']) assert.doesNotMatch(await source(name), /(from|import\()\s*['"][^'"]*http-scope-text/, name);
  // In the connector it feeds only the run's scopeLabel and limitations.
  const uses = connector.match(/\b(httpScopeText|httpLimitations)\(/g) ?? [];
  assert.equal(uses.length, 2);
  assert.match(connector, /scopeLabel: targetScopePrefix\([^)]*\) \+ httpScopeText\(/);
  assert.match(connector, /limitations: httpLimitations\(/);
});

test('rewording the scope line and limitations leaves a saved run valid (identity does not depend on wording)', async t => {
  const server = createServer((req, res) => { res.writeHead(req.url === '/me' ? 200 : 404, { 'Content-Type': 'application/json', Connection: 'close' }); res.end('{"user":"m"}'); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const run = await runHttpAssessment({ id: 'w', name: 'W', applicationId: 'w-app', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b', contextId: 'ctx',
    targetContext: 'operator-forwarded', targetLabel: 'Acme staging', actors: { anon: { principalId: 'anonymous' } }, requiredControlIds: ['ME'], observers: [],
    checks: [{ id: 'ME', title: 'Me', category: 'x', severity: 'control', actorId: 'anon', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] }, { env: {} });
  validateHttpRunEvidence(run);
  const reworded = structuredClone(run);
  reworded.scopeLabel = 'operator-forwarded target: Acme staging. Entirely different wording.';
  reworded.limitations = reworded.limitations.map((l, i) => l.includes(FORWARDER_MARKER) ? `Reworded: an ${FORWARDER_MARKER} carried this run.` : `Reworded limitation ${i}.`);
  validateHttpRunEvidence(reworded);
});
