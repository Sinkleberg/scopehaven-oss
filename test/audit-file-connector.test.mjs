// The audit-log file observer as a profile observer type: the connector sends the
// witness request (a GET the app logs, tagged with the start mark's nonce) after each
// check's settle, after every other observer's end mark, and collects each audit-file
// window right after its own end mark. The shared validator binds the window.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, appendFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { AUDIT_FILE_QUIET_DEFAULT_MS } from '../src/http-scope-text.mjs';
import { AUDIT_FILE_LIMITS } from '../integrations/observers/audit-file.mjs';
import { buildObservers as buildSequenceObservers } from '../integrations/sequences/cli.mjs';

const TOKEN = 'synthetic-member-token', env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
// An app that writes an Open WebUI-style audit line per answered request, to one log per name.
//   mode 'secure': the forbidden edit is refused (403, logged 403)
//   mode 'late':   refused at once, then a background job commits it lateMs later (logged 200)
//   witnessDelayMs: per log, how long the witness route takes to answer
//   witnessWrites:  the witness route logs an internal POST /notes/n-own/edit 200 before its own line
async function auditedApp(t, { mode = 'secure', lateMs = 300, logWitness = true, logs = ['a'], witnessDelayMs = {}, witnessWrites = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-audit-app-'));
  const logPaths = Object.fromEntries(logs.map(name => [name, join(dir, `${name}.log`)])), dbPath = join(dir, 'app.db');
  for (const p of Object.values(logPaths)) writeFileSync(p, '');
  const db = new DatabaseSync(dbPath); db.exec('CREATE TABLE pings (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT);');
  let origin; const timers = new Set();
  const log = (name, verb, url, status) => appendFileSync(logPaths[name], `${JSON.stringify({ verb, request_uri: `${origin}${url}`, response_status_code: status, user: { id: 'u-member' } })}\n`);
  const later = (ms, fn) => { const timer = setTimeout(() => { timers.delete(timer); fn(); }, ms); timers.add(timer); };
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.url === '/me') { reply(200, { user: 'member-1' }); return logs.forEach(n => log(n, 'GET', req.url, 200)); }
    if (req.method === 'POST' && req.url === '/notes/n-other/edit') {
      reply(403, { error: 'forbidden' }); log('a', 'POST', req.url, 403);
      if (mode === 'late') later(lateMs, () => log('a', 'POST', req.url, 200));
      return;
    }
    const witness = /^\/api\/witness\/([a-z]+)\?/.exec(req.url);
    if (req.method === 'GET' && witness) {
      const name = witness[1];
      return later(witnessDelayMs[name] ?? 0, () => {
        db.prepare('INSERT INTO pings (at) VALUES (?)').run(new Date().toISOString());
        if (witnessWrites) log(name, 'POST', '/notes/n-own/edit', 200); // the witness route's own (internal) write
        reply(200, { ok: true }); if (logWitness) log(name, 'GET', req.url, 200);
      });
    }
    if (req.method === 'POST' && req.url === '/noop') { reply(200, { ok: true }); return log('a', 'POST', req.url, 200); }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await new Promise(r => { server.close(r); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { origin, logPaths, dbPath };
}
const auditLog = (app, name = 'a', extra = {}) => ({ id: name, type: 'audit-file', path: app.logPaths[name], origin: app.origin, settleMs: 500, quietMs: 200, witnessWaitMs: 2000,
  rules: [{ name: 'note.update', method: 'POST', path: '/notes/{id}/edit', refusedStatuses: [403] }, { name: 'witness', method: 'GET', path: `/api/witness/${name}`, operation: 'read' }, { name: 'noop', method: 'POST', path: '/noop', operation: 'insert' }],
  ignore: [{ method: 'GET', path: '/me' }], logActors: { 'member-1': 'u-member' },
  witness: { rule: 'witness', actorId: 'member', method: 'GET', path: `/api/witness/${name}` }, ...extra });
const profile = (app, observers, checks, extraActors = {}) => ({ id: 'audited', name: 'Audited app', applicationId: 'audited-app', origin: app.origin, buildLabel: 'b1', contextId: 'synthetic-audited',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' }, ...extraActors }, requiredControlIds: ['WHOAMI'], observers,
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] }, ...checks] });
const editOther = { id: 'OTHER-NOTE', title: "Cannot edit another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {}, evidenceRequirement: 'backend',
  assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'file-audit-log', actor: 'member-1', name: 'note.update' } }] };
const row = (run, id) => run.results.find(r => r.id === id);
const effect = r => r.assertions.find(a => a.name.startsWith('Observed effect'));
const pings = app => { const reader = new DatabaseSync(app.dbPath, { readOnly: true }); try { return reader.prepare('SELECT count(*) AS c FROM pings').get().c; } finally { reader.close(); } };

test('audit-file in a profile: a refused edit is proven absent from the app\'s own log, with backend evidence observed', async t => {
  const app = await auditedApp(t, { mode: 'secure' });
  const p = profile(app, [auditLog(app)], [editOther]);
  const run = await runHttpAssessment(p, { env });
  const r = row(run, 'OTHER-NOTE');
  // Custody (src/custody.mjs): the app writes its own log, so the decided absence reads inconclusive in a boundary check.
  assert.deepEqual([r.status, r.backendEvidence, effect(r).custodyReason], ['inconclusive', 'observed', 'subject-writable-custody'], JSON.stringify(r.assertions));
  const w = r.trace[1].data.windows[0];
  assert.deepEqual([w.source, w.instanceId, w.coverage, w.lineage.observer], ['file-audit-log', 'audit-file-a', 'complete', 'audit-log-file']);
  assert.deepEqual(w.events.map(e => [e.name, e.outcome]), [['note.update', 'denied']], 'the witness line is never an event');
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  const limitation = run.limitations.find(l => l.startsWith('Audit-log file observers'));
  for (const phrase of ['rely on the app logging every request on their rule routes', 'For each check that declares effects', 'quietMs: a 200 ms', 'not counted in the run\'s time budget'])
    assert.ok(limitation.includes(phrase), phrase);
  assert.ok(!/its own side effects fall outside every window/.test(limitation));
});

test('audit-file in a profile: a commit logged 300 ms after the 403, before the witness, fails the check; an unlogged witness is inconclusive', async t => {
  const late = await auditedApp(t, { mode: 'late', lateMs: 300 });
  const run = await runHttpAssessment(profile(late, [auditLog(late)], [editOther]), { env });
  const r = row(run, 'OTHER-NOTE');
  assert.equal(r.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass');
  assert.deepEqual([r.status, r.backendEvidence], ['fail', 'observed'], effect(r).actual);
  validateHttpRunEvidence(run);
  const silent = await auditedApp(t, { mode: 'secure', logWitness: false });
  const unwitnessed = await runHttpAssessment(profile(silent, [auditLog(silent)], [editOther]), { env });
  const u = row(unwitnessed, 'OTHER-NOTE');
  assert.equal(u.status, 'inconclusive'); assert.match(effect(u).actual, /audit-witness-not-logged/);
  validateHttpRunEvidence(unwitnessed);
});

test('recheck H-1: a second observer\'s slow witness does not cancel the first one\'s quiet period', async t => {
  // A's witness answers at once (about 500 ms after the edit, after the settle); B's takes 300 ms, more than
  // lateCollectMs. The forbidden commit is logged about 700 ms after A's witness: after a collect that waited
  // only for B's round trip, but well inside A's declared quietMs of 1500.
  const app = await auditedApp(t, { mode: 'late', lateMs: 1200, logs: ['a', 'b'], witnessDelayMs: { b: 300 } });
  const run = await runHttpAssessment(profile(app, [auditLog(app, 'a', { quietMs: 1500 }), auditLog(app, 'b', { rules: [auditLog(app, 'b').rules[1]] })], [editOther]), { env });
  const r = row(run, 'OTHER-NOTE');
  assert.notEqual(effect(r).status, 'pass', effect(r).actual);
  assert.notEqual(r.status, 'pass');
  validateHttpRunEvidence(run);
});

test('recheck H-2: a rule line the witness route itself logs is never attributed to the check and cannot satisfy effect.exists', async t => {
  const app = await auditedApp(t, { mode: 'secure', witnessWrites: true });
  const ownEdit = { id: 'OWN-EDIT', title: 'An own edit is committed', category: 'allowed-use', severity: 'high', actorId: 'member', method: 'POST', path: '/noop', body: {}, evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'file-audit-log', name: 'note.update' } }] };
  const run = await runHttpAssessment(profile(app, [auditLog(app)], [ownEdit]), { env });
  const r = row(run, 'OWN-EDIT');
  assert.notEqual(effect(r).status, 'pass', effect(r).actual);
  const w = r.trace[1].data.windows[0];
  assert.equal(w.events.filter(e => e.name === 'note.update').length, 0);
  assert.equal(w.coverage, 'partial'); assert.match(w.reason, /audit-line-after-witness-request/);
  validateHttpRunEvidence(run);
});

test('the witness is a GET: it is never sent as a POST, and its route\'s database write stays outside another observer\'s window', async t => {
  const app = await auditedApp(t, { mode: 'secure' });
  const db = { id: 'db', type: 'sqlite-snapshot', path: app.dbPath, settleMs: 500, tables: [{ table: 'pings', key: 'id' }] };
  const noop = id => ({ id, title: 'A no-op is not a ping', category: 'allowed-use', severity: 'high', actorId: 'member', method: 'POST', path: '/noop', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'pings', operation: 'insert' } }] });
  const run = await runHttpAssessment(profile(app, [auditLog(app), db], [noop('NOOP'), noop('NOOP-2')]), { env });
  assert.equal(pings(app), 2, 'one witness per effect check');
  for (const id of ['NOOP', 'NOOP-2']) assert.equal(row(run, id).trace[1].data.windows.find(w => w.source === 'sql-snapshot').events.length, 0, id);
  validateHttpRunEvidence(run);
});

test('recheck L-2: a witness actor whose credential is not set refuses the run instead of sending anonymously', async t => {
  const app = await auditedApp(t);
  const auditor = { auditor: { principalId: 'auditor-1', credentialEnv: 'SCOPEHAVEN_TARGET_AUDITOR' } };
  const log = auditLog(app, 'a', { witness: { ...auditLog(app).witness, actorId: 'auditor' } });
  await assert.rejects(runHttpAssessment(profile(app, [log], [editOther], auditor), { env }), /credentials are missing or invalid/);
});

test('recheck L-3: audit-file configuration and the witness are validated with the profile, before any request', async t => {
  const app = await auditedApp(t);
  const reject = (edit, pattern) => { const o = auditLog(app); edit(o); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile(app, [o], [editOther])] }), pattern); };
  reject(o => { delete o.witness; }, /"witness" is \{ rule, actorId, method: "GET", path \} and nothing else/);
  reject(o => { o.witness.method = 'POST'; }, /the witness must be a GET the app logs/);
  reject(o => { o.witness.body = {}; }, /and nothing else/);
  reject(o => { o.witness.stateful = true; }, /and nothing else/);
  reject(o => { o.witness.actorId = 'stranger'; }, /must be a declared actor/);
  reject(o => { o.witness.path = '/api/witness/a?scopehaven%5Fwitness=x'; }, /cannot carry its own witness parameter/);
  reject(o => { o.witness.path = '/api/witness/a?SCOPEHAVEN_WITNESS=x'; }, /cannot carry its own witness parameter/);
  reject(o => { o.rules.push({ name: 'witness2', method: 'GET', path: '/api/witness/{x}' }); }, /must match exactly one rule: its witness rule/);
  reject(o => { o.witness.path = '/api/other'; }, /must match exactly one rule: its witness rule/);
  reject(o => { o.quietMs = 50; }, /"quietMs" must be an integer from 100 to 10000/);
  reject(o => { o.witnessWaitMs = 'soon'; }, /"witnessWaitMs" must be an integer from 0 to 30000/);
  reject(o => { o.rules[0].method = 'FETCH'; }, /each audit rule needs a name and an HTTP method/);
  reject(o => { o.rules[0].refusedStatuses = [500]; }, /may only list 4xx/);
  reject(o => { o.origin = 'http://127.0.0.1:1/x'; }, /scheme:\/\/host:port only/);
  assert.equal(AUDIT_FILE_QUIET_DEFAULT_MS, AUDIT_FILE_LIMITS.quietMs, 'the limitation text default mirrors the observer default');
});

test('recheck L-4: sequences refuse an audit-file observer (they send no witness)', async t => {
  const app = await auditedApp(t);
  assert.throws(() => buildSequenceObservers([auditLog(app)]), /Sequences cannot use an audit-file observer/);
});
