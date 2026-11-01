// pg-snapshot as a profile observer type, end to end through runHttpAssessment
// and the shared validator, against a scripted fake Postgres (no real database).
// Also pins the shared look-alike module into both identity sets.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { validateWindow, evaluateEffectAssertion, exactFor } from '../src/effect-events.mjs';
import { digest } from '../src/domain.mjs';
import { projectHttpInternal } from '../src/contract-http.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { CONVERSATION_EVALUATOR_FILES } from '../integrations/conversations/validation.mjs';
import { scriptedDb, USER, PASSWORD } from '../integrations/observers/fixtures/fake-postgres.mjs';

const TOKEN = 'synthetic-bob-token', env = { SCOPEHAVEN_TARGET_BOB: TOKEN, SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
async function app(t) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    if (req.url === '/chats/c1/messages') return reply(403, { error: 'forbidden' });
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const pgObserver = port => ({ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }], settleMs: 250 });
const profile = (origin, observers) => ({ id: 'chatbot', name: 'Chatbot', applicationId: 'chatbot-app', origin, buildLabel: 'b1', contextId: 'synthetic-chatbot',
  actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI'], observers,
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
    { id: 'BOB-ALICE-CHAT', title: "Bob cannot read alice's chat, and the read changes nothing", category: 'object-access', severity: 'high', actorId: 'bob', method: 'GET', path: '/chats/c1/messages', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1' } }] },
  ] });
const rows = xmin => [['c1', xmin, 'h1'], ['c2', '701', 'h2']];
// Marks: start() at run start, the settlement mark before the first check (src/http-settlement.mjs), the check's
// start and end marks, then the final mark after the last check plus the settle.
const states = (startXmin, endXmin) => [{ snapshot: '800:800:', tables: { Chat: rows(startXmin) } }, { snapshot: '800:800:', tables: { Chat: rows(startXmin) } }, { snapshot: '800:800:', tables: { Chat: rows(startXmin) } },
  { snapshot: '805:805:', tables: { Chat: rows(endXmin) } }, { snapshot: '805:805:', tables: { Chat: rows(endXmin) } }];
const row = (run, id) => run.results.find(r => r.id === id);

test('pg-snapshot in a profile: an unchanged row version proves the denied read changed nothing (backend observed)', async t => {
  const origin = await app(t), db = await scriptedDb(t, states('700', '700'));
  const p = profile(origin, [pgObserver(db.port)]);
  const run = await runHttpAssessment(p, { env });
  const r = row(run, 'BOB-ALICE-CHAT');
  // Custody (src/custody.mjs): the snapshot reads the app's own store, so the decided absence reads inconclusive in a boundary check.
  assert.deepEqual([r.status, r.backendEvidence, r.trace[1].data.effects[0].custodyReason], ['inconclusive', 'observed', 'subject-writable-custody'], JSON.stringify(r.assertions));
  const w = r.trace[1].data.windows[0];
  assert.deepEqual([w.instanceId, w.lineage.observer, w.coverage, w.exact[0].method, w.exact[0].auditSha256], ['pg-snapshot-db', 'postgres-snapshot-diff', 'net-only', 'xmin', null]);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  assert.ok(run.limitations.some(l => l.startsWith('Postgres snapshot observers (db)')));
  // The exact method is bound to the observer type: relabelling it as an audited change column is refused.
  const forged = structuredClone(run), fw = row(forged, 'BOB-ALICE-CHAT').trace[1].data.windows[0];
  // Only the observer-type binding refuses this: without marks it is a well-formed change-column entry.
  delete fw.exact[0].method; delete fw.exact[0].marks; fw.exact[0].auditSha256 = digest('not an audit');
  validateWindow(fw);
  const fr = row(forged, 'BOB-ALICE-CHAT'); fr.evidenceDigest = digest({ evidence: fr.trace[0].data, effects: fr.trace[1].data, assertions: fr.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

test('pg-snapshot in a profile: a new row version during the denied read fails the check', async t => {
  const origin = await app(t), db = await scriptedDb(t, states('700', '804'));
  const run = await runHttpAssessment(profile(origin, [pgObserver(db.port)]), { env });
  const r = row(run, 'BOB-ALICE-CHAT');
  assert.equal(r.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass');
  assert.deepEqual([r.status, r.backendEvidence], ['fail', 'observed']);
  validateHttpRunEvidence(run);
});

test('pg-snapshot profiles: loopback, plain identifiers, and the credential only through credentialEnv', () => {
  const reject = (edit, pattern) => { const o = pgObserver(5432); edit(o); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile('http://127.0.0.1:4000', [o])] }), pattern); };
  reject(o => { o.password = 'x'; }, /its credential comes only from credentialEnv/);
  reject(o => { o.user = 'admin'; }, /its credential comes only from credentialEnv/);
  reject(o => { o.host = 'localhost'; }, /literal loopback address 127\.0\.0\.1/);
  reject(o => { delete o.credentialEnv; }, /declare "credentialEnv"/);
  reject(o => { o.credentialEnv = 'PGPASSWORD'; }, /SCOPEHAVEN_TARGET_/);
  reject(o => { o.tables = [{ table: 'Chat; DROP', key: 'id' }]; }, /plain identifiers/);
  reject(o => { o.database = 'app db'; }, /plain identifier/);
  reject(o => { o.lockFallback = true; }, /lockFallback/);
  reject(o => { o.tables = [{ table: 'Chat', key: 'id' }, { table: 'Chat', key: 'id', schema: 'audit' }]; }, /each table name is declared once per pg-snapshot observer/);
  reject(o => { o.rowsPerTable = 500000; }, /"rowsPerTable" must be an integer from 1 to 200000/);
  reject(o => { o.statementTimeoutMs = 90000; }, /"statementTimeoutMs" must be an integer from 500 to 60000/);
});

test('exact entries: an xmin entry carries no audit hash, and a change-column entry must', () => {
  const base = { source: 'sql-snapshot', instanceId: 'x', scope: { operations: ['update'], names: ['Chat'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null, events: [] };
  const entry = extra => ({ ...base, exact: [{ name: 'Chat', ambiguousResources: [], violated: false, basis: 'b', ...extra }] });
  const marks = { startXmax: '800', endXmax: '800', inProgress: 0 };
  validateWindow(entry({ method: 'xmin', auditSha256: null, presentResources: ['Chat/c1'], marks }));
  assert.throws(() => validateWindow(entry({ method: 'xmin', auditSha256: null, marks })), /exact/, 'an xmin entry records which selected rows it saw');
  validateWindow(entry({ auditSha256: 'a'.repeat(64), presentResources: [] }));
  // Review R3 M2: every exact entry records presentResources, a change-column entry too (no legacy table-wide exactness).
  assert.throws(() => validateWindow(entry({ auditSha256: 'a'.repeat(64) })), /exact/, 'a change-column entry records which selected rows it saw');
  assert.throws(() => validateWindow(entry({ method: 'xmin', auditSha256: 'a'.repeat(64), presentResources: [], marks })), /exact/);
  assert.throws(() => validateWindow(entry({ auditSha256: null })), /exact/);
  assert.throws(() => validateWindow(entry({ method: 'guess', auditSha256: null })), /exact/);
});

test('the invalid-credential look-alike is one shared module, in both the HTTP and the conversation identity sets', async () => {
  const connector = await readFile(new URL('../src/http-connector.mjs', import.meta.url), 'utf8');
  assert.match(/const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(connector)[1], /'lookalike\.mjs'/);
  assert.ok(CONVERSATION_EVALUATOR_FILES.includes('src/lookalike.mjs'));
  const conversation = await readFile(new URL('../integrations/conversations/conversation.mjs', import.meta.url), 'utf8');
  assert.match(connector, /import \{ lookalikeCredential \} from '\.\/lookalike\.mjs'/);
  assert.match(conversation, /import \{ lookalikeCredential \} from '\.\.\/\.\.\/src\/lookalike\.mjs'/);
  assert.doesNotMatch(connector, /export function lookalikeCredential/, 'defined once, in the shared module');
});

test('exact entries: quiescent and marks are checked against each other, and an exact name appears once', () => {
  const base = { source: 'sql-snapshot', instanceId: 'x', scope: { operations: ['update'], names: ['Chat'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null, events: [] };
  const xmin = extra => ({ name: 'Chat', method: 'xmin', auditSha256: null, ambiguousResources: [], presentResources: [], violated: false, basis: 'b', marks: { startXmax: '800', endXmax: '800', inProgress: 0 }, ...extra });
  const win = (...exact) => ({ ...base, exact });
  validateWindow(win(xmin({ quiescent: true })));
  const refuse = (w, why) => assert.throws(() => validateWindow(w), /exact/, why);
  refuse(win(xmin(), xmin()), 'duplicate exact entries');
  refuse(win({ name: 'Chat', ambiguousResources: [], violated: false, basis: 'b', auditSha256: 'a'.repeat(64), quiescent: true }), 'quiescent on a change-column entry');
  refuse(win(xmin({ quiescent: false })), 'quiescent is only ever true');
  refuse(win(xmin({ quiescent: true, marks: { startXmax: '800', endXmax: '805', inProgress: 0 } })), 'quiescent with xmax moved');
  refuse(win(xmin({ quiescent: true, marks: { startXmax: '800', endXmax: '800', inProgress: 1 } })), 'quiescent with a transaction in progress');
  refuse(win(xmin({ quiescent: true, ambiguousResources: ['Chat/c1'] })), 'quiescent with ambiguous rows');
  refuse(win(xmin({ marks: undefined })), 'an xmin entry records its marks');
  refuse(win(xmin({ marks: { startXmax: '800', endXmax: '790', inProgress: 0 } })), 'end xmax below start xmax must be violated');
  validateWindow(win(xmin({ violated: true, marks: { startXmax: '800', endXmax: '790', inProgress: 0 } })));
  refuse(win({ name: 'Chat', ambiguousResources: [], violated: false, basis: 'b', auditSha256: 'a'.repeat(64), marks: { startXmax: '1', endXmax: '1', inProgress: 0 } }), 'marks only on xmin entries');
});

test('L8 fix 6b: a quiescent pg-snapshot window decides insert and delete absence; nothing weaker does, and updates are unchanged', () => {
  const xmin = extra => ({ name: 'messages', method: 'xmin', auditSha256: null, ambiguousResources: [], presentResources: ['messages/m1'], violated: false, basis: 'b', marks: { startXmax: '800', endXmax: '800', inProgress: 0 }, ...extra });
  const win = (entry, extra = {}) => validateWindow({ source: 'sql-snapshot', instanceId: 'pg-1', scope: { operations: ['insert', 'update', 'delete'], names: ['messages'], actorAttribution: 'none', evidence: 'authoritative' },
    coverage: 'net-only', reason: 'net-change-between-snapshots', events: [], exact: [entry], ...extra });
  const verdict = (kind, select, w) => evaluateEffectAssertion({ kind, select: { source: 'sql-snapshot', name: 'messages', ...select } }, [w]).verdict;
  const quiet = win(xmin({ quiescent: true })), busy = win(xmin({ marks: { startXmax: '800', endXmax: '803', inProgress: 0 } }));
  // The stop/revoke drill's rows: no message or run inserted on a window where nothing committed anywhere.
  for (const select of [{ operation: 'insert' }, { operation: 'insert', resource: 'messages/m9' }, { operation: 'insert', resource: { prefix: 'messages/' } }, { operation: 'delete', resource: 'messages/m1' }]) {
    assert.equal(verdict('effect.none', select, quiet), 'pass', JSON.stringify(select));
    assert.equal(verdict('effect.exists', select, quiet), 'fail', JSON.stringify(select));
    assert.equal(verdict('effect.none', select, busy), 'missing', `not quiescent: ${JSON.stringify(select)}`);
  }
  // Never exact: an actor-pinned selector, a selector with no operation, effect.count, and a change-column entry (no quiescence).
  assert.equal(exactFor(quiet, { source: 'sql-snapshot', name: 'messages', operation: 'insert', actor: 'u1' }, 'effect.none'), null);
  assert.equal(exactFor(quiet, { source: 'sql-snapshot', name: 'messages' }, 'effect.none'), null);
  assert.equal(exactFor(quiet, { source: 'sql-snapshot', name: 'messages', operation: 'insert' }, 'effect.count'), null);
  const audited = { name: 'messages', auditSha256: 'a'.repeat(64), ambiguousResources: [], presentResources: [], violated: false, basis: 'b' };
  assert.equal(exactFor(win(audited), { source: 'sql-snapshot', name: 'messages', operation: 'insert' }, 'effect.none'), null);
  // A hand-made entry that claims quiescence without being an xmin entry decides nothing (validateWindow refuses it too).
  assert.equal(exactFor({ source: 'sql-snapshot', exact: [{ ...audited, quiescent: true }] }, { name: 'messages', operation: 'delete' }, 'effect.none'), null);
  assert.equal(exactFor({ source: 'sql-snapshot', exact: [xmin({ quiescent: true, ambiguousResources: ['messages/m2'] })] }, { name: 'messages', operation: 'insert' }, 'effect.none'), null);
  // Updates read as they did: a row seen at both marks is exact; a table-wide update absence needs quiescence.
  assert.equal(verdict('effect.none', { operation: 'update', resource: 'messages/m1' }, busy), 'pass');
  assert.equal(verdict('effect.none', { operation: 'update' }, busy), 'missing');
  assert.equal(verdict('effect.none', { operation: 'update' }, quiet), 'pass');
});
test('pg-snapshot in a profile: a prefix selector with a typo does not pass over a real update (H-A, end to end)', async t => {
  const origin = await app(t), db = await scriptedDb(t, states('700', '804'));
  const p = profile(origin, [pgObserver(db.port)]);
  p.checks[1].effects = [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: { prefix: 'chat/c1' } } }];
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const run = await runHttpAssessment(p, { env });
  assert.notEqual(row(run, 'BOB-ALICE-CHAT').status, 'pass');
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
});

test('R4 L-a and L-c: exact-entry lists are type-checked first, and every marks shape and boundary is checked', () => {
  const base = { source: 'sql-snapshot', instanceId: 'x', scope: { operations: ['update'], names: ['Chat'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null, events: [] };
  const xmin = extra => ({ ...base, exact: [{ name: 'Chat', method: 'xmin', auditSha256: null, ambiguousResources: [], presentResources: [], violated: false, basis: 'b', marks: { startXmax: '800', endXmax: '800', inProgress: 0 }, ...extra }] });
  const refuse = (w, why) => assert.throws(() => validateWindow(w), e => e.code === 'exact', why);
  // L-a: a missing or null list is an exact refusal, never a TypeError.
  for (const v of [undefined, null, 'Chat/c1']) { refuse(xmin({ quiescent: true, ambiguousResources: v }), `ambiguousResources ${v}`); refuse(xmin({ presentResources: v }), `presentResources ${v}`); }
  // L-c: marks shapes.
  for (const marks of [{ startXmax: '', endXmax: '800', inProgress: 0 }, { startXmax: 800, endXmax: '800', inProgress: 0 }, { startXmax: '0800', endXmax: '800', inProgress: 0 },
    { startXmax: '800', endXmax: '800', inProgress: 0, extra: 1 }, { startXmax: '800', endXmax: '800', inProgress: -1 }, { startXmax: '800', endXmax: '800', inProgress: 0.5 }, null, []]) refuse(xmin({ marks }), JSON.stringify(marks));
  refuse(xmin({ quiescent: true, marks: { startXmax: '800', endXmax: '801', inProgress: 0 } }), 'quiescent over a moved xmax');
  refuse(xmin({ marks: { startXmax: '1000', endXmax: '999', inProgress: 0 } }), 'a regressed xmax across a digit boundary must be violated');
  validateWindow(xmin({ marks: { startXmax: '999', endXmax: '1000', inProgress: 0 } }));
  validateWindow(xmin({ violated: true, marks: { startXmax: '1000', endXmax: '999', inProgress: 0 } }));
});

test('R5 M-1: a run refused for a sealed window says why (detail effect-window-exact), through the validator and the contract view', async t => {
  const origin = await app(t), db = await scriptedDb(t, states('700', '700'));
  const run = await runHttpAssessment(profile(origin, [pgObserver(db.port)]), { env });
  validateHttpRunEvidence(run);
  const forged = structuredClone(run), fr = row(forged, 'BOB-ALICE-CHAT');
  delete fr.trace[1].data.windows[0].exact[0].presentResources; // the main-era shape
  fr.evidenceDigest = digest({ evidence: fr.trace[0].data, effects: fr.trace[1].data, assertions: fr.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence' && e.message === 'invalid-run-evidence' && e.detail === 'effect-window-exact');
  // The gate is where a user meets a refused saved run: the summary carries the detail.
  const refused = summarizeGate({ candidate: forged });
  assert.deepEqual([refused.outcome, refused.reasons, refused.detail], ['config-or-runtime-error', ['invalid-run-evidence'], 'effect-window-exact']);
  assert.equal(summarizeGate({ candidate: run }).detail, undefined);
  // The contract view reads only http-contract/1 runs so far (later versions are pending); for the ones it reads, runEvidence carries the same detail.
  assert.equal(projectHttpInternal(forged).view.reason, 'http-version-pending');
});
