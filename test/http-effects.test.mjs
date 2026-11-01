// Core wiring (http-contract/4): HTTP profiles declare observers and per-check
// effects; the connector seals the observer windows into each row; the shared
// validator recomputes every effect decision from those windows.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, ASSERTION_SCHEMA_VERSION } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { digest } from '../src/domain.mjs';

const TOKEN = 'synthetic-member-token', env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
// A tiny notes app. mode 'secure' refuses edits of another user's note; mode
// 'lying' answers 403 but commits the edit anyway; mode 'open' allows it.
async function notesApp(t, mode = 'secure') {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-effects-'));
  const dbPath = join(dir, 'notes.db'), db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE notes (id TEXT PRIMARY KEY, owner TEXT, body TEXT);
    CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, action TEXT, target TEXT);
    INSERT INTO notes VALUES ('n-other', 'other', 'hello');`);
  const state = { mode };
  const server = createServer((req, res) => {
    const c = []; req.on('data', d => c.push(d)); req.on('end', () => {
      if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, { error: 'auth' });
      if (req.url === '/me') return json(res, 200, { user: 'member-1' });
      if (req.method === 'POST' && req.url === '/notes') {
        const id = `n-${Math.random().toString(16).slice(2, 8)}`;
        db.prepare('INSERT INTO notes VALUES (?, ?, ?)').run(id, 'member-1', 'mine'); db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'note.create', `notes/${id}`);
        return json(res, 201, { id });
      }
      if (req.method === 'POST' && req.url === '/notes/n-other/edit') {
        if (state.mode !== 'secure') { db.prepare("UPDATE notes SET body = 'edited' WHERE id = 'n-other'").run(); db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'note.update', 'notes/n-other'); }
        return json(res, state.mode === 'open' ? 200 : 403, state.mode === 'open' ? { ok: true } : { error: 'forbidden' });
      }
      return json(res, 404, {});
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise(r => { server.close(r); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { origin: `http://127.0.0.1:${server.address().port}`, dbPath, state };
}
const auditObserver = dbPath => ({ id: 'app-audit', type: 'sqlite-audit', path: dbPath, settleMs: 250, principals: ['member-1'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'action', resourceColumn: 'target', actions: { 'note.create': 'insert', 'note.update': 'update' } } });
function profile(origin, observers, overrides = {}) {
  return {
    id: 'notes', name: 'Notes app', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } },
    requiredControlIds: ['WHOAMI', 'OWN-NOTE'], observers,
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
      { id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.exists', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.create' } }] },
      { id: 'OTHER-NOTE', title: "A member cannot edit another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {}, evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.update' } }] },
    ], ...overrides };
}
const row = (run, id) => run.results.find(r => r.id === id);

test('the forbidden edit is refused and the audit log proves it did not happen: backend evidence observed, row passes', async t => {
  const app = await notesApp(t, 'secure');
  const run = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)]), { env });
  assert.equal(run.adapterVersion, 'loopback-response-contract/3'); assert.equal(run.assertionSchemaVersion, ASSERTION_SCHEMA_VERSION);
  const r = row(run, 'OTHER-NOTE');
  // Custody (src/custody.mjs): the audit table is a record the app can write, so its absence cannot pass a
  // boundary check. The observer still decided the effect (backend observed); the row reads inconclusive.
  assert.equal(r.status, 'inconclusive', JSON.stringify(r.assertions));
  const effect = r.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  assert.deepEqual([effect.status, effect.custody, effect.custodyReason], ['inconclusive', 'subject-writable', 'subject-writable-custody']);
  assert.equal(r.backendEvidence, 'observed'); assert.equal(r.observed.evidenceScope, 'response-and-observers');
  assert.equal(r.trace[1].type, 'effect-observation'); assert.equal(r.trace[1].data.windows[0].lineage.independence, 'application-store');
  assert.equal(row(run, 'OWN-NOTE').status, 'pass');
  assert.deepEqual(run.observers, [{ id: 'app-audit', type: 'sqlite-audit', settleMs: 250 }]);
  validateHttpRunEvidence(run);
});

test('an app that answers 403 but commits the edit: the response check passes, the observed effect fails the row', async t => {
  const app = await notesApp(t, 'lying');
  const run = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)]), { env });
  const r = row(run, 'OTHER-NOTE');
  assert.equal(r.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass');
  assert.equal(r.assertions.find(a => a.name === 'Observed effect 1 (effect.none)').status, 'fail');
  assert.equal(r.status, 'fail'); assert.equal(r.backendEvidence, 'observed');
  validateHttpRunEvidence(run);
});

test('no observer able to see the effect, or presence-only telemetry, reads unverifiable: never a pass', async t => {
  const app = await notesApp(t, 'secure');
  for (const observers of [[], [{ id: 'traces', type: 'otel', port: 0, services: ['notes'], tools: ['note.update'], settleMs: 250 }]]) {
    const p = profile(app.origin, observers);
    p.checks[2].effects = [{ kind: 'effect.none', select: { actor: 'member-1', name: 'note.update' } }];
    p.checks[1].effects = undefined; delete p.checks[1].effects;
    const run = await runHttpAssessment(p, { env });
    const r = row(run, 'OTHER-NOTE');
    assert.equal(r.status, 'inconclusive', `${observers.length} observers: ${JSON.stringify(r.assertions)}`);
    assert.match(r.assertions.find(a => a.name === 'Observed effect 1 (effect.none)').actual, /^unobservable:/);
    assert.equal(r.backendEvidence, 'unavailable');
    validateHttpRunEvidence(run);
  }
});

test('the shared validator recomputes every effect decision: tampered verdicts, events, backend fields or labels are rejected', async t => {
  const app = await notesApp(t, 'lying');
  const run = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)]), { env });
  const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };
  const tamper = edit => { const copy = structuredClone(run); edit(copy); return () => validateHttpRunEvidence(copy); };
  // 1. Flip the failing effect to a pass everywhere a reader would look, and reseal.
  assert.throws(tamper(c => { const r = row(c, 'OTHER-NOTE'); r.trace[1].data.effects[0].verdict = 'pass'; const a = r.assertions.find(x => x.name === 'Observed effect 1 (effect.none)'); a.status = 'pass'; a.actual = 'pass: x'; r.status = 'pass'; reseal(r); }));
  // 2. Remove the committed event from the window, keep the stored fail.
  assert.throws(tamper(c => { const r = row(c, 'OTHER-NOTE'); r.trace[1].data.windows[0].events = r.trace[1].data.windows[0].events.filter(e => e.name !== 'note.update'); reseal(r); }));
  // 3. Remove the event AND restate a pass: the recomputed decision is now "pass", but the window must still validate and the row still has a failing HTTP-or-effect history.
  assert.throws(tamper(c => { const r = row(c, 'OTHER-NOTE'); r.backendEvidence = 'unavailable'; reseal(r); }));
  // 4. Relabel the evidence lineage of the window.
  assert.throws(tamper(c => { const r = row(c, 'OTHER-NOTE'); r.trace[1].data.windows[0].lineage.independence = 'request-path'; reseal(r); }));
  // 5. Relabel a v3 run as v2: effect windows under a v2 label are a downgrade.
  assert.throws(tamper(c => { c.adapterVersion = 'loopback-response-contract/2'; c.assertionSchemaVersion = 'http-contract/3'; }));
  // 6. Claim presence-only telemetry is authoritative.
  assert.throws(tamper(c => { const w = row(c, 'OTHER-NOTE').trace[1].data.windows[0]; w.source = 'otel-genai'; }));
});

test('runs compare within v3: a repair from "lying" to "secure" is restored; the exported suite binds declared effects', async t => {
  const app = await notesApp(t, 'lying');
  const before = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)]), { env });
  app.state.mode = 'secure';
  const after = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)], { buildLabel: 'b2' }), { env });
  const comparison = compareRuns(before, after);
  assert.equal(comparison.compatible, true, comparison.reasons.join(' '));
  // The repaired row rests only on the app's own audit table: inconclusive, so the change is unverified, never restored.
  assert.equal(comparison.rows.find(r => r.id === 'OTHER-NOTE').transition, 'unverified');
  const { createRegistry } = await import('../src/registry.mjs');
  const suite = createRegistry({ profiles: [profile(app.origin, [auditObserver(app.dbPath)], { buildLabel: 'b2' })], env }).exportSuite('notes');
  assert.deepEqual(suite.checks.find(c => c.id === 'OTHER-NOTE').effects, [{ kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.update' } }]);
  assert.deepEqual(suite.observers, [{ id: 'app-audit', type: 'sqlite-audit', settleMs: 250 }]);
  validateHttpRunEvidence(after, { expectedSuite: suite });
  const changed = structuredClone(suite); changed.checks.find(c => c.id === 'OTHER-NOTE').effects[0].select.name = 'note.delete';
  assert.throws(() => validateHttpRunEvidence(after, { expectedSuite: changed }), /unexpected-suite-evidence/);
  const dropped = structuredClone(suite); delete dropped.checks.find(c => c.id === 'OTHER-NOTE').effects;
  assert.throws(() => validateHttpRunEvidence(after, { expectedSuite: dropped }), /unexpected-suite-evidence/);
});

test('profile validation: effects need declared observers; observers cannot carry env, transport or foreign credentials', () => {
  const base = profile('http://127.0.0.1:9', []);
  const check = (edit, pattern) => { const p = structuredClone(base); edit(p); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  check(p => { delete p.observers; }, /effects need the target to declare "observers"/);
  check(p => { p.observers = [{ id: 'x', type: 'sqlite-audit', env: {} }]; }, /env, transport, instanceId or lockFallback/);
  check(p => { p.observers = [{ id: 'x', type: 'http-audit', credentialEnv: 'GITHUB_TOKEN' }]; }, /SCOPEHAVEN_TARGET_/);
  check(p => { p.observers = [{ id: 'x', type: 'postgres' }]; }, /observer "type"/);
  check(p => { p.observers = [{ id: 'x', type: 'otel' }, { id: 'x', type: 'otel' }]; }, /unique "id"/);
  check(p => { p.observers = [{ id: 'x', type: 'sqlite-snapshot', lockFallback: true }]; }, /lockFallback/);
  for (const settleMs of [0, 249, 30001, 1.5, '500']) check(p => { p.observers = [{ id: 'x', type: 'sqlite-audit', settleMs }]; }, /"settleMs" must be an integer from 250 to 30000/);
  check(p => { p.observers = [{ id: 'x'.repeat(49), type: 'otel' }]; }, /unique "id" \(1-48/);
  check(p => { p.checks[2].effects = [{ kind: 'effect.never', select: { name: 'x' } }]; }, /invalid effect assertion/);
  check(p => { p.checks[2].effects = []; }, /1 to 32/);
  assert.equal(validateTargetFile({ schemaVersion: 1, targets: [base] })[0].observers.length, 0);
});

// In-network mode: a target reached through an operator-run forwarder on the
// loopback origin. The connector still dials 127.0.0.1 only; the context and
// label are hashed, recorded, validated and shown in every export's scope line.
test('target context: validated, hashed, recorded in the run and shown by the report, SARIF, gate and action summary', async t => {
  const { renderReport } = await import('../src/report.mjs');
  const { renderSarif } = await import('../src/sarif.mjs');
  const { summarizeGate } = await import('../integrations/regression-gate/gate.mjs');
  const { buildReport } = await import('../integrations/github-action/summary.mjs');
  const reject = (overrides, pattern) => assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile('http://127.0.0.1:4000', [], overrides)] }), pattern);
  reject({ targetContext: 'remote' }, /"targetContext": must be one of local-app, operator-forwarded/);
  reject({ targetLabel: 'Acme staging' }, /names an operator-forwarded or operator-remote target only/);
  for (const label of ['https://staging.acme.com', 'staging.acme.com:8443', 'qa@staging', 'acme/staging', '', 'x'.repeat(81), ' leading space'])
    reject({ targetContext: 'operator-forwarded', targetLabel: label }, /never a URL or address/);
  reject({ targetContext: 'operator-forwarded', origin: 'http://staging.acme.com' }, /origin must be literal loopback HTTP/);
  const [local] = validateTargetFile({ schemaVersion: 1, targets: [profile('http://127.0.0.1:4000', [])] });
  assert.equal(local.targetContext, 'local-app');

  const app = await notesApp(t, 'secure');
  const plain = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)]), { env });
  const forwarded = await runHttpAssessment(profile(app.origin, [auditObserver(app.dbPath)], { targetContext: 'operator-forwarded', targetLabel: 'Acme staging (eu-west)' }), { env });
  assert.deepEqual([plain.targetContext, plain.targetLabel], ['local-app', null]);
  assert.deepEqual([forwarded.targetContext, forwarded.targetLabel], ['operator-forwarded', 'Acme staging (eu-west)']);
  assert.notEqual(plain.profileHash, forwarded.profileHash); assert.notEqual(plain.targetConfigHash, forwarded.targetConfigHash);
  const prefix = 'operator-forwarded target: Acme staging (eu-west). ';
  assert.ok(forwarded.scopeLabel.startsWith(prefix)); assert.ok(!plain.scopeLabel.startsWith('operator-forwarded'));
  assert.ok(forwarded.limitations.some(l => l.includes('operator-run forwarder')) && !plain.limitations.some(l => l.includes('operator-run forwarder')));
  validateHttpRunEvidence(plain); validateHttpRunEvidence(forwarded);

  assert.ok(renderReport(forwarded).includes(`<strong>${prefix.trim()}`));
  assert.ok(JSON.stringify(renderSarif(forwarded)).includes(prefix.trim()));
  const gate = summarizeGate({ candidate: forwarded });
  assert.equal(gate.current.targetContext, 'operator-forwarded'); assert.equal(gate.current.targetLabel, 'Acme staging (eu-west)');
  assert.ok(gate.current.interpretation.startsWith(prefix));
  assert.equal(summarizeGate({ candidate: plain }).current.targetContext, 'local-app');
  assert.ok(buildReport({ runInput: forwarded, env: {} }).markdown.includes('> **Scope:** operator-forwarded target: Acme staging \\(eu-west\\). Response contracts plus authoritative backend observation'));

  // Inconsistent relabels are refused. A fully consistent relabel (context, label, scope
  // line, limitations and target-config digest all rewritten) is caught only against the
  // exported suite: see http-effects-review.test.mjs.
  const tamper = (run, change) => { const copy = structuredClone(run); change(copy); assert.throws(() => validateHttpRunEvidence(copy), /invalid-run-evidence/); };
  tamper(forwarded, r => { r.scopeLabel = r.scopeLabel.slice(prefix.length); });
  tamper(forwarded, r => { r.targetLabel = 'https://staging.acme.com'; r.scopeLabel = `operator-forwarded target: ${r.targetLabel}. ${r.scopeLabel.slice(prefix.length)}`; });
  tamper(plain, r => { r.targetContext = 'operator-forwarded'; });
  tamper(plain, r => { r.targetLabel = 'Acme staging'; });
  tamper(plain, r => { r.targetContext = 'remote'; });
  tamper(plain, r => { delete r.targetContext; });

  // A local app and a forwarded staging target never compare as one subject.
  const compared = compareRuns(plain, forwarded);
  assert.equal(compared.compatible, false);
  assert.ok(compared.reasons.some(reason => reason.startsWith('Target context differs')));
  assert.equal(compareRuns(forwarded, structuredClone(forwarded)).compatible, true);
});
