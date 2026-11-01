// Watch-first: a watch run on the owned example app (examples/observed-support-app.mjs: loopback, synthetic data,
// fixed-text assistant, no model), the profile drafted from it, the approval gate every profile load keeps, and the
// drafted checks run on fixed and defective builds. No provider, no model, no network beyond loopback.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runWatch, validateWatch, verifyRecordId, watchId } from './watch.mjs';
import { draftFromWatch } from './draft.mjs';
import { admitDraftedLines, approveLines, draftedLines, hasDraftedLines, DraftedLineError } from './lines.mjs';
import { main } from './cli.mjs';
import { validateTargetFile, contractDigest } from '../../src/contracts.mjs';
import { loadProfiles } from '../../src/registry.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { canonical, sha256 } from '../policy-import/matrix.mjs';
import { AUTHORIZATION_SCHEMA, AuthorizationError, checksumAuthorization, guardObserverFactory } from '../../src/authorization.mjs';
import { createObservedSupportApp, bindExampleProfile } from '../../examples/observed-support-app.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CLI = fileURLToPath(new URL('../../src/cli.mjs', import.meta.url));
const whoami = (id, title) => ({ id, title, category: 'Identity', severity: 'control', actorId: 'agentB', method: 'GET', path: '/api/me', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'agent-b@globex.test' }] });
const AUDIT = { id: 'app-audit', type: 'sqlite-audit', path: '/x', settleMs: 300, principals: ['agent-a', 'agent-b'],
  audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'action', resourceColumn: 'target', actions: { 'refund.create': 'insert', 'discount.create': 'insert', 'subscription.cancel': 'update' } } };
const TABLES = { id: 'app-tables', type: 'sqlite-snapshot', path: '/x', settleMs: 300, tables: [{ table: 'refunds', key: 'id' }, { table: 'discounts', key: 'id' }] };
const PAYMENTS = { id: 'app-payments', type: 'egress-recorder', port: 47100, routing: 'base-url', destinations: [{ host: 'payments.example', paths: ['/v1/refunds/A-1', '/v1/refunds/B-1', '/v1/refunds/B-2'] }],
  routes: [{ prefix: '/pay/', host: 'payments.example' }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }], witness: { actorId: 'agentB', method: 'GET', path: '/api/egress-witness', host: 'witness.scopehaven.invalid' }, settleMs: 500 };
const skeleton = ({ observers = [AUDIT, TABLES, PAYMENTS], turns } = {}) => ({ schema: 'scopehaven-watch/1',
  target: { id: 'example-watch', name: 'Example support app (watched)', applicationId: 'example-support', origin: 'http://127.0.0.1:8080', buildLabel: 'example support app, local test build', contextId: 'synthetic-two-company',
    actors: { agentB: { principalId: 'agent-b', tenantId: 'globex', role: 'agent', credentialEnv: 'SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B', identityValue: 'agent-b@globex.test' } }, observers },
  checks: { first: [whoami('B-WHOAMI', 'Agent B session is agent B')], last: [whoami('B-WHOAMI-AFTER', 'Agent B session is still agent B')] },
  requiredControlIds: ['B-WHOAMI', 'B-WHOAMI-AFTER'],
  turns: turns ?? [{ id: 'T1', actorId: 'agentB', method: 'GET', path: '/api/orders/B-1' }, { id: 'T2', actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { reason: 'watch' } }] });
const bind = (target, app) => bindExampleProfile({ schemaVersion: 1, targets: [target] }, app).targets[0];
async function onApp(build, fn) { const app = await createObservedSupportApp({ build, egress: true }); try { return await fn(app); } finally { await app.close(); } }
async function watched(build = 'secure', options) {
  return onApp(build, async app => { const watch = { ...skeleton(options), target: bind(skeleton(options).target, app) }; return { watch, record: await runWatch(watch, { env: app.env }) }; });
}
async function assessOn(build, profile) {
  return onApp(build, async app => {
    const run = await runHttpAssessment(validateTargetFile({ schemaVersion: 1, targets: [bind(profile.targets[0], app)] })[0], { env: app.env });
    return Object.fromEntries(run.results.map(r => [r.id, r]));
  });
}
const effectRow = row => row.assertions.find(a => a.name.startsWith('Observed effect 1 '));
const approveAll = profile => admitDraftedLines(approveLines(profile, { approvedBy: 'Test Operator' }).profile);
let secure;
test.before(async () => { secure = await watched('secure'); });

test('the watch run records each turn and its windows, judges nothing, and its record is sealed to its watch file', () => {
  const { watch, record } = secure;
  assert.equal(record.schema, 'scopehaven-watch-record/1');
  assert.ok(verifyRecordId(record));
  assert.equal(record.watchId, watchId(watch));
  assert.deepEqual(record.turns.map(t => [t.id, t.response.status]), [['T1', 200], ['T2', 201]]);
  for (const turn of record.turns) assert.deepEqual(turn.windows.map(w => w.observer), ['app-audit', 'app-tables', 'app-payments']);
  assert.equal(record.turns[0].windows.reduce((n, w) => n + w.events.length, 0), 0, 'a read writes nothing');
  const t2 = record.turns[1].windows;
  assert.deepEqual(t2.map(w => w.coverage), ['complete', 'net-only', 'complete']);
  assert.deepEqual(t2.flatMap(w => w.events.map(e => [e.source, e.actor, e.operation, e.name, e.resource, e.outcome])), [
    ['sql-audit-table', 'agent-b', 'insert', 'refund.create', 'orders/B-1', 'committed'],
    ['sql-snapshot', null, 'insert', 'refunds', 'refunds/1', 'committed'],
    ['http-egress', null, 'send', 'payments.example', 'POST /v1/refunds/B-1', 'committed']]);
  // No verdict, assertion or decision anywhere in the record.
  assert.doesNotMatch(JSON.stringify(record), /"(verdict|assertions|decision|severity|expected)":/);
  const edited = structuredClone(record); edited.turns[1].response.status = 200;
  assert.equal(verifyRecordId(edited), false);
});

test('the draft proposes an effect.only check and its allowed-use twin per write turn, every line drafted and unapproved', () => {
  const { profile, report } = draftFromWatch(secure.watch, secure.record);
  const target = profile.targets[0];
  assert.deepEqual(target.checks.map(c => c.id), ['B-WHOAMI', 'WF-T2-USE', 'WF-T2-ONLY', 'B-WHOAMI-AFTER']);
  assert.deepEqual(target.requiredControlIds, ['B-WHOAMI', 'B-WHOAMI-AFTER', 'WF-T2-USE']);
  const use = target.checks[1], only = target.checks[2];
  for (const line of [only, use]) { assert.equal(line.drafted, 'observed'); assert.equal(line.approved, false); assert.equal(line.observed.record, secure.record.recordId); assert.equal(line.observed.turn, 'T2'); }
  for (const hand of [target.checks[0], target.checks[3]]) assert.equal(Object.hasOwn(hand, 'drafted'), false, 'hand-written checks pass through unmarked');
  assert.deepEqual([only.method, only.path, only.body, only.severity, only.category, only.evidenceRequirement], ['POST', '/api/orders/B-1/refunds', { reason: 'watch' }, 'high', 'Collateral', 'backend']);
  // The audit row names the order the request named (pinned) and its actor; the payment call's declared path names it too.
  // The snapshot reads net-only, so it cannot decide a pass and is left out of the clause, with a warning.
  assert.deepEqual(only.effects, [{ kind: 'effect.only', allow: [], sources: ['http-egress', 'sql-audit-table'], expect: [
    { select: { source: 'sql-audit-table', actor: 'agent-b', operation: 'insert', name: 'refund.create', resource: 'orders/B-1' }, count: 1 },
    { select: { source: 'http-egress', operation: 'send', name: 'payments.example', resource: 'POST /v1/refunds/B-1' }, count: 1 }] }]);
  assert.deepEqual(use.effects, only.effects[0].expect.map(e => ({ kind: 'effect.count', select: e.select, expected: e.count })));
  assert.deepEqual([use.severity, use.evidenceRequirement, use.assertions], ['control', 'response', [{ kind: 'status.equals', expected: 201 }]]);
  assert.deepEqual(report.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]), [['T1', 'no-write-observed']]);
  assert.deepEqual(report.judgedSources, [{ source: 'http-egress', custody: 'independent' }, { source: 'sql-audit-table', custody: 'subject-writable' }]);
  assert.ok(report.warnings.some(w => w.startsWith('source sql-snapshot (app-tables) is left out')));
  assert.ok(report.warnings.some(w => w.includes('sql-audit-table, a record the application can write: they can fail on it, never pass on it')));
  assert.ok(report.warnings.some(w => w.startsWith('WF-T2-USE: the twin sends POST /api/orders/B-1/refunds before WF-T2-ONLY does')));
  assert.deepEqual(report.inventory.destinations, [{ host: 'payments.example', resources: ['POST /v1/refunds/B-1'] }]);
  assert.deepEqual(report.inventory.tables, [{ table: 'refunds', operations: ['insert'], columns: 'not-recorded' }]);
  assert.deepEqual(report.inventory.identities, { actorsUsed: ['agentB'], principalsSeen: [{ principal: 'agent-b', observers: ['app-audit'] }] });
  assert.equal(report.approved, false);
  const { draftId, ...body } = report;
  assert.equal(draftId, sha256(canonical(body)));
  assert.deepEqual(report.selfTest, [{ id: 'WF-T2-USE', outcome: 'proven' }, { id: 'WF-T2-ONLY', outcome: 'partial' }]);
  // Observers are kept as declared: none narrowed to what one run touched.
  assert.deepEqual(target.observers, secure.watch.target.observers);
});

test('the draft refuses an edited record, a record from another watch file, and a watch with nothing to draft', () => {
  const edited = structuredClone(secure.record); edited.turns[1].windows[0].events = [];
  assert.throws(() => draftFromWatch(secure.watch, edited), /edited without recomputing its recordId/);
  const other = structuredClone(secure.watch); other.turns[1].body = { reason: 'another' };
  assert.throws(() => draftFromWatch(other, secure.record), /not from this watch file/);
  const reads = skeleton({ turns: [{ id: 'T1', actorId: 'agentB', method: 'GET', path: '/api/orders/B-1' }] });
  const body = { ...structuredClone(secure.record), watchId: watchId(reads), turns: [secure.record.turns[0]] };
  delete body.recordId;
  assert.throws(() => draftFromWatch(reads, { ...body, recordId: sha256(canonical(body)) }), /Nothing to draft: T1 no-write-observed/);
});

test('every profile load refuses an unapproved drafted line, and reads an approved one as the hand-written line', async t => {
  const { profile } = draftFromWatch(secure.watch, secure.record);
  assert.throws(() => admitDraftedLines(profile), e => e instanceof DraftedLineError && e.code === 'drafted-line-unapproved' && /^The profile has 2 drafted line\(s\) no one has approved/.test(e.message)
    && e.lines.join('|') === 'target "example-watch" check "WF-T2-USE"|target "example-watch" check "WF-T2-ONLY"');
  const approved = approveAll(profile);
  assert.equal(hasDraftedLines(approved), false);
  // The same lines written by hand: identical profile hash, so approval adds nothing a run or a comparison reads.
  const byHand = structuredClone(profile);
  for (const c of byHand.targets[0].checks) { delete c.drafted; delete c.approved; delete c.observed; }
  assert.equal(contractDigest(validateTargetFile(approved)[0]), contractDigest(validateTargetFile(byHand)[0]));
  // Through the loader every command uses (check-config, assess, gate, the dashboard).
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const draftedFile = join(dir, 'drafted.targets.json'), approvedFile = join(dir, 'approved.targets.json');
  await writeFile(draftedFile, JSON.stringify(profile)); await writeFile(approvedFile, JSON.stringify(approveLines(profile, { approvedBy: 'Test Operator' }).profile));
  await assert.rejects(loadProfiles(draftedFile), /drafted line\(s\) no one has approved/);
  assert.deepEqual((await loadProfiles(approvedFile)).map(p => p.id), ['example-watch']);
  const run = args => new Promise(resolve => execFile(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH } }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr })));
  const refused = await run(['--check-config', '--config', draftedFile]);
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /Scopehaven could not run: The profile has 2 drafted line\(s\) no one has approved .*check "WF-T2-USE"; target "example-watch" check "WF-T2-ONLY"\./);
  const accepted = await run(['--check-config', '--config', approvedFile]);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stdout).targets.find(x => x.id === 'example-watch').checks, 4);
});

test('the approval markers are read exactly: approvedBy required, never on an unapproved line, only on lines, one source', () => {
  const { profile } = draftFromWatch(secure.watch, secure.record);
  const edit = fn => { const p = structuredClone(profile); fn(p.targets[0]); return p; };
  const code = p => { try { admitDraftedLines(p); return 'admitted'; } catch (e) { return e.code; } };
  const approvedHere = c => Object.assign(c, { approved: true, approvedBy: 'A Person' });
  assert.equal(code(edit(t => t.checks.forEach(c => c.drafted && approvedHere(c)))), 'admitted');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); delete t.checks[1].approvedBy; })), 'drafted-marker-invalid');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); t.checks[1].approvedBy = '  '; })), 'drafted-marker-invalid');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); t.checks[1].approved = 'yes'; })), 'drafted-marker-invalid');
  assert.equal(code(edit(t => { t.checks[1].approvedBy = 'A Person'; })), 'drafted-marker-invalid');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); t.checks[1].drafted = 'declared'; })), 'drafted-marker-invalid');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); t.approved = true; })), 'drafted-marker-misplaced');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); t.checks[0].approved = false; t.checks[0].drafted = 'observed'; })), 'drafted-line-unapproved', 'a marker added to a hand-written line gates it too');
  // An observer or an actor line is gated the same way.
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); Object.assign(t.observers[0], { drafted: 'observed', approved: false }); })), 'drafted-line-unapproved');
  assert.equal(code(edit(t => { t.checks.forEach(c => c.drafted && approvedHere(c)); Object.assign(t.actors.agentB, { drafted: 'observed', approved: false }); })), 'drafted-line-unapproved');
  // A request body is the application's data: "approved" there is not a marker, and a profile without markers is the same object.
  const handWritten = { schemaVersion: 1, targets: [{ ...secure.watch.target, requiredControlIds: ['B-WHOAMI'], checks: [whoami('B-WHOAMI', 'Agent B session is agent B'),
    { id: 'B-APPROVE', title: 'B approves a refund', category: 'Allowed use', severity: 'high', actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { approved: true, approvedBy: 'x', drafted: 'observed' }, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] }] }] };
  assert.equal(admitDraftedLines(handWritten), handWritten);
  assert.equal(hasDraftedLines(handWritten), false);
  // Approval by id: a typo is refused, never read as an approval; the rest stay unapproved.
  assert.throws(() => approveLines(profile, { approvedBy: 'A Person', ids: ['WF-T2-0NLY'] }), /No drafted line "WF-T2-0NLY"/);
  assert.throws(() => approveLines(profile, { approvedBy: '' }), /Name the person approving/);
  const partly = approveLines(profile, { approvedBy: 'A Person', ids: ['WF-T2-ONLY'] });
  assert.equal(partly.approved, 1);
  assert.deepEqual(draftedLines(partly.profile).map(l => [l.id, l.approved]), [['WF-T2-USE', false], ['WF-T2-ONLY', true]]);
  assert.throws(() => admitDraftedLines(partly.profile), /1 drafted line\(s\) no one has approved .*WF-T2-USE/);
});

test('approved, the drafted checks pass the build they were watched on, fail collateral writes, and a refuse-everything build fails the twin', async () => {
  const approved = approveAll(draftFromWatch(secure.watch, secure.record).profile);
  const fixed = await assessOn('secure', approved);
  assert.equal(fixed['WF-T2-USE'].status, 'pass');
  // The app's own audit table can fail "nothing else happened" but never pass it (custody): inconclusive, not pass.
  assert.equal(fixed['WF-T2-ONLY'].status, 'inconclusive');
  assert.match(effectRow(fixed['WF-T2-ONLY']).actual, /was expected \(2\) or allowed \(0\).*Custody/);
  for (const [build, collateral] of [['refund-plus-discount', 'insert discount.create orders/B-1'], ['refund-plus-cancel', 'update subscription.cancel subscriptions/globex-monthly']]) {
    const defective = await assessOn(build, approved);
    assert.equal(defective['WF-T2-ONLY'].status, 'fail', build);
    assert.ok(effectRow(defective['WF-T2-ONLY']).actual.includes(collateral), `${build}: ${effectRow(defective['WF-T2-ONLY']).actual}`);
    assert.equal(defective['WF-T2-USE'].status, 'pass', build);
  }
  const refuses = await assessOn('refuse-b', approved);
  assert.equal(refuses['WF-T2-USE'].status, 'fail');
  assert.notEqual(refuses['WF-T2-ONLY'].status, 'pass');
  // Narrowed by a person to the independent source, the clause can pass, and still fails a payment for the wrong order.
  const narrowed = structuredClone(approved);
  const only = narrowed.targets[0].checks.find(c => c.id === 'WF-T2-ONLY');
  only.effects[0].sources = ['http-egress']; only.effects[0].expect = only.effects[0].expect.filter(e => e.select.source === 'http-egress');
  assert.equal((await assessOn('secure', narrowed))['WF-T2-ONLY'].status, 'pass');
  assert.equal((await assessOn('pay-wrong-order', narrowed))['WF-T2-ONLY'].status, 'fail');
});

test('a write the application answered with a refusal, or attributed to someone else, is never proposed as expected', async () => {
  const cross = [{ id: 'X1', actorId: 'agentB', method: 'POST', path: '/api/orders/A-1/refunds', body: { reason: 'watch' } }, { id: 'X2', actorId: 'agentB', method: 'POST', path: '/api/orders/B-2/refunds', body: { reason: 'watch' } }];
  const leaky = await watched('leaky', { turns: cross });
  const { profile, report } = draftFromWatch(leaky.watch, leaky.record);
  assert.deepEqual(report.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]), [['X1', 'write-with-refusal-status']]);
  assert.ok(report.warnings.includes('turn X1: the application answered 404 and still committed 3 write(s); review it by hand'));
  assert.deepEqual(profile.targets[0].checks.filter(c => c.drafted).map(c => c.id), ['WF-X2-USE', 'WF-X2-ONLY']);
  const owner = await watched('leaky-owner-audit', { observers: [AUDIT], turns: [{ id: 'X1', actorId: 'agentB', method: 'POST', path: '/api/assistant/chat', body: { orderId: 'A-1', action: 'refund' } }, cross[1]] });
  const audited = draftFromWatch(owner.watch, owner.record);
  assert.deepEqual(audited.report.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]), [['X1', 'write-by-another-principal']]);
});

test('an observer that does not declare the acting principal is drafted with it added, by inference, and gated like any line', async () => {
  const partial = await watched('secure', { observers: [{ ...AUDIT, principals: ['agent-a'] }] });
  const { profile, report } = draftFromWatch(partial.watch, partial.record);
  const observer = profile.targets[0].observers[0];
  assert.deepEqual([observer.principals, observer.drafted, observer.approved, observer.observed.basis], [['agent-a', 'agent-b'], 'observed', false, 'inferred-from-turn-actor']);
  assert.equal(profile.targets[0].checks.find(c => c.id === 'WF-T2-ONLY').effects[0].expect[0].select.actor, 'agent-b');
  assert.deepEqual(report.inventory.identities.principalsSeen, [{ principal: 'unlisted (a principal the observer does not declare)', observers: ['app-audit'] }]);
  assert.throws(() => admitDraftedLines(approveLines(profile, { approvedBy: 'A', ids: ['WF-T2-ONLY', 'WF-T2-USE'] }).profile), /observer "app-audit"/);
  assert.equal((await assessOn('secure', approveAll(profile)))['WF-T2-USE'].status, 'pass');
});

test('the watch file is checked before anything is sent: loopback targets only, unique turns, no checks inside the target', () => {
  const w = skeleton();
  assert.equal(validateWatch(w), w);
  assert.throws(() => validateWatch({ ...w, schema: 'x' }), /schema "scopehaven-watch\/1"/);
  assert.throws(() => validateWatch({ ...w, target: { ...w.target, targetContext: 'operator-remote' } }), /local application on loopback only/);
  assert.throws(() => validateWatch({ ...w, target: { ...w.target, checks: [] } }), /without "checks"/);
  assert.throws(() => validateWatch({ ...w, turns: [w.turns[0], w.turns[0]] }), /unique id/);
  assert.throws(() => validateWatch({ ...w, turns: [{ ...w.turns[0], assertions: [] }] }), /a turn is/);
  assert.throws(() => validateWatch({ ...w, turns: [{ ...w.turns[0], actorId: 'nobody' }] }), /actor/i);
  assert.throws(() => validateWatch({ ...w, extra: 1 }), /no field "extra"/);
});

test('the CLI writes new private files only, refuses to overwrite, and lists and approves lines', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first cli ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const files = { watch: join(dir, 'watch.json'), record: join(dir, 'record.json'), profile: join(dir, 'drafted.json'), report: join(dir, 'report.json'), approved: join(dir, 'approved.json') };
  await writeFile(files.watch, JSON.stringify(secure.watch)); await writeFile(files.record, JSON.stringify(secure.record));
  const out = [];
  assert.equal(await main(['draft', files.watch, '--record', files.record, '--out-profile', files.profile, '--out-report', files.report], { log: s => out.push(s) }), 0);
  for (const f of [files.profile, files.report]) assert.equal((await stat(f)).mode & 0o777, 0o600);
  await assert.rejects(main(['draft', files.watch, '--record', files.record, '--out-profile', files.profile, '--out-report', join(dir, 'r2.json')], { log: () => {} }), /EEXIST/);
  assert.equal(await main(['lines', files.profile], { log: s => out.push(s) }), 0);
  assert.equal(JSON.parse(out.at(-1)).unapproved, 2);
  assert.equal(await main(['approve', files.profile, '--approved-by', 'Test Operator', '--out', files.approved], { log: s => out.push(s) }), 0);
  assert.equal(admitDraftedLines(JSON.parse(await readFile(files.approved, 'utf8'))).targets[0].checks.length, 4);
  await assert.rejects(main(['watch', files.watch, '--out', join(dir, 'w.json')], { log: () => {} }), /authorization record/);
  await assert.rejects(main(['draft', files.watch, '--record', files.record, '--out-profile', join(dir, 'a'), '--out-report', join(dir, 'b'), '--bogus', 'x'], { log: () => {} }), /Unsupported option --bogus/);
});

test('no model, provider or outside host anywhere in the module: it imports the product and the policy-import draft only', async () => {
  for (const name of ['watch.mjs', 'draft.mjs', 'lines.mjs', 'cli.mjs']) {
    const source = await readFile(join(HERE, name), 'utf8');
    const imports = [...source.matchAll(/^import [^;]* from '([^']+)';$/gm), ...source.matchAll(/\bimport\('([^']+)'\)/g)].map(m => m[1]);
    for (const spec of imports) assert.match(spec, /^(node:(fs\/promises|path|url)|\.\/[a-z-]+\.mjs|\.\.\/\.\.\/src\/[a-z-]+\.mjs|\.\.\/policy-import\/matrix\.mjs|\.\.\/observers\/factory\.mjs)$/, `${name} imports ${spec}`);
    // The import allowlist above leaves no room for a provider SDK; no network call of its own either.
    assert.doesNotMatch(source, /\bfetch\(|https:\/\/|createConnection|net\.connect/i, name);
  }
});

test('each turn is marked, sent, settled for the largest declared settle, then marked and collected, in that order', async () => {
  const calls = [];
  const fake = { kind: 'sqlite-audit', instanceId: 'sqlite-audit-app-audit', source: 'sql-audit-table', scope: { operations: ['insert'], names: ['refund.create'], actorAttribution: 'principal', evidence: 'authoritative' },
    start: async () => calls.push('start'), stop: async () => calls.push('stop'), mark: async () => { calls.push('mark'); return { at: calls.length }; },
    collect: async (from, to) => { calls.push(`collect ${from.at}-${to.at}`); return { events: [], coverage: 'complete', reason: null }; } };
  const watch = skeleton({ observers: [AUDIT, { ...TABLES, settleMs: 700 }], turns: [{ id: 'T2', actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { reason: 'watch' } }] });
  const record = await runWatch(watch, { env: { SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B: 'a'.repeat(32) }, factory: () => [fake, { ...fake, instanceId: 'sqlite-snapshot-app-tables' }],
    transport: async (origin, request) => { calls.push(`send ${request.method} ${request.path}`); return { status: 201, complete: true }; }, sleep: async ms => calls.push(`sleep ${ms}`) });
  assert.deepEqual(calls, ['start', 'start', 'mark', 'mark', 'send POST /api/orders/B-1/refunds', 'sleep 700', 'mark', 'mark', 'collect 3-7', 'collect 4-8', 'stop', 'stop']);
  assert.deepEqual(record.turns[0].response, { status: 201, complete: true, transport: 'complete' });
});

const reseal = record => { const { recordId, ...body } = record; return { ...body, recordId: sha256(canonical(body)) }; };
const TWO = [{ id: 'T2', actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { reason: 'watch' } }, { id: 'T3', actorId: 'agentB', method: 'POST', path: '/api/orders/B-2/refunds', body: { reason: 'watch' } }];
const egressOnly = profile => { const p = structuredClone(profile); for (const t of p.targets) for (const c of t.checks) if (c.id.endsWith('-ONLY')) { c.effects[0].sources = ['http-egress']; c.effects[0].expect = c.effects[0].expect.filter(e => e.select.source === 'http-egress'); } return p; };

test('with several write turns each is drafted in a target of its own, so every effect.only clause can be decided', async () => {
  const two = await watched('secure', { turns: TWO });
  const { profile, report } = draftFromWatch(two.watch, two.record);
  assert.deepEqual(profile.targets.map(t => [t.id, t.checks.map(c => c.id), t.requiredControlIds]), [
    ['example-watch-T2', ['B-WHOAMI', 'WF-T2-USE', 'WF-T2-ONLY', 'B-WHOAMI-AFTER'], ['B-WHOAMI', 'B-WHOAMI-AFTER', 'WF-T2-USE']],
    ['example-watch-T3', ['B-WHOAMI', 'WF-T3-USE', 'WF-T3-ONLY', 'B-WHOAMI-AFTER'], ['B-WHOAMI', 'B-WHOAMI-AFTER', 'WF-T3-USE']]]);
  assert.deepEqual(report.targets, ['example-watch-T2', 'example-watch-T3']);
  assert.ok(report.warnings.some(w => w.startsWith('2 write turns: each is drafted in a target of its own')));
  // Narrowed to the independent source, as the custody warning advises: both pass on the build they were watched on.
  const narrowed = egressOnly(approveAll(profile));
  for (const target of narrowed.targets) {
    const rows = await assessOn('secure', { schemaVersion: 1, targets: [target] });
    assert.equal(rows[target.checks[2].id].status, 'pass', target.id);
  }
});

test('the watch CLI runs under an authorization record, and stops, writing no record, when its window ends mid-watch', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first auth ')); t.after(() => rm(dir, { recursive: true, force: true }));
  await onApp('secure', async app => {
    const watch = { ...skeleton({ observers: [AUDIT] }), target: bind(skeleton({ observers: [AUDIT] }).target, app) };
    const watchFile = join(dir, 'watch.json'); await writeFile(watchFile, JSON.stringify(watch));
    const record = (untilMs, name) => { const now = Date.now(), iso = ms => new Date(ms).toISOString();
      const sealed = checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: `watch-${name}`, target: { id: 'example-watch', applicationId: 'example-support' }, origins: [app.origin], identities: ['agent-b'],
        validFrom: iso(now - 60000), validUntil: iso(now + untilMs), signer: { name: 'A. Example', role: 'Owner' }, signedAt: iso(now - 60000) });
      const path = join(dir, `${name}.json`); return writeFile(path, JSON.stringify(sealed)).then(() => path); };
    const out = join(dir, 'record.json');
    assert.equal(await main(['watch', watchFile, '--authorization', await record(600000, 'open'), '--out', out], { env: app.env, log: () => {} }), 0);
    assert.ok(verifyRecordId(JSON.parse(await readFile(out, 'utf8'))));
    // A window ending during the watch: the turns' settle waits outlast it.
    const long = { ...watch, target: { ...watch.target, observers: [{ ...watch.target.observers[0], settleMs: 700 }] }, turns: [watch.turns[1], { ...watch.turns[1], id: 'T3' }, { ...watch.turns[1], id: 'T4' }, { ...watch.turns[1], id: 'T5' }] };
    const longFile = join(dir, 'long.json'); await writeFile(longFile, JSON.stringify(long));
    const before = app.refundCount(), ended = join(dir, 'ended.json');
    await assert.rejects(main(['watch', longFile, '--authorization', await record(1200, 'short'), '--out', ended], { env: app.env, log: () => {} }), e => e.code === 'authorization-window-ended');
    await assert.rejects(stat(ended), /ENOENT/);
    assert.ok(app.refundCount() - before < 4, 'no turn is sent after the window ends');
  });
});

test('a write another source attributes to someone else is never proposed, even when that source cannot judge the clause', async () => {
  const two = await watched('secure', { turns: TWO });
  const edited = structuredClone(two.record);
  edited.turns[0].windows.find(w => w.observer === 'app-audit').coverage = 'partial';
  edited.turns[1].windows.find(w => w.observer === 'app-audit').events[0].actor = 'agent-a';
  const { profile, report } = draftFromWatch(two.watch, reseal(edited));
  assert.deepEqual(report.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]), [['T3', 'write-by-another-principal']]);
  assert.deepEqual(report.judgedSources.map(j => j.source), ['http-egress'], 'the partial audit source judges nothing');
  assert.deepEqual(profile.targets[0].checks.map(c => c.id), ['B-WHOAMI', 'WF-T2-USE', 'WF-T2-ONLY', 'B-WHOAMI-AFTER']);
});

test('a turn is not drafted when its response was incomplete, when no observer could report it, or when only an unjudged source saw it', () => {
  const edit = fn => { const r = structuredClone(secure.record); fn(r.turns[1]); return reseal(r); };
  const reason = r => { try { return draftFromWatch(secure.watch, r).report.notDrafted.map(n => n.reason.split(':')[0]); } catch (e) { return e.notDrafted.map(n => n.reason.split(':')[0]); } };
  assert.deepEqual(reason(edit(t => { t.response = { status: null, complete: false, transport: 'timeout' }; })), ['no-write-observed', 'response-incomplete']);
  assert.deepEqual(reason(edit(t => { for (const w of t.windows) { w.events = []; w.coverage = 'failed'; } })), ['no-write-observed', 'no-complete-window']);
  // Every window of the write turn reads failed except the net-only snapshot, which saw the write: nothing can judge it.
  assert.deepEqual(reason(edit(t => { for (const w of t.windows) if (w.observer !== 'app-tables') { w.events = []; w.coverage = 'failed'; } })), ['no-write-observed', 'no-deciding-source']);
});

test('a profile whose only drafted line is an unapproved observer is refused at load, and --strip writes the plain profile', async t => {
  const partial = await watched('secure', { observers: [{ ...AUDIT, principals: ['agent-a'] }] });
  const { profile } = draftFromWatch(partial.watch, partial.record);
  const observerOnly = approveLines(profile, { approvedBy: 'A Person', ids: ['WF-T2-USE', 'WF-T2-ONLY'] }).profile;
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first strip ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'observer-only.json'); await writeFile(file, JSON.stringify(observerOnly));
  await assert.rejects(loadProfiles(file), /1 drafted line\(s\) no one has approved .*observer "app-audit"/);
  await assert.rejects(main(['approve', file, '--approved-by', 'A Person', '--line', 'WF-T2-USE', '--strip', '--out', join(dir, 'x.json')], { log: () => {} }), /no one has approved/);
  const plainFile = join(dir, 'plain.json');
  assert.equal(await main(['approve', file, '--approved-by', 'A Person', '--strip', '--out', plainFile], { log: () => {} }), 0);
  const plain = JSON.parse(await readFile(plainFile, 'utf8'));
  assert.equal(hasDraftedLines(plain), false);
  assert.deepEqual(validateTargetFile(plain)[0].observers[0].principals, ['agent-a', 'agent-b'], 'a tool that validates the file directly reads it');
});

test('an observer with a witness is marked for it (head split), sent its witness, then marked and collected, as a run does', async () => {
  const calls = [];
  const witnessed = { kind: 'egress-recorder', instanceId: 'egress-recorder-app-payments', source: 'http-egress', scope: { operations: ['send'], names: ['payments.example'], actorAttribution: 'none', evidence: 'authoritative' },
    witnessRequest: { actorId: 'agentB', method: 'GET', path: '/api/egress-witness' },
    start: async () => {}, stop: async () => {}, mark: async () => { calls.push('mark'); return { witnessNonce: `n${calls.length}` }; },
    markWitnessRequest: async (from, options) => calls.push(`markWitnessRequest ${from.witnessNonce} ${JSON.stringify(options)}`),
    collect: async (from, to) => { calls.push(`collect ${from.witnessNonce}-${to.witnessNonce}`); return { events: [], coverage: 'complete', reason: null }; } };
  const failing = { ...witnessed, witnessRequest: undefined, instanceId: 'sqlite-audit-app-audit', source: 'sql-audit-table', scope: { operations: ['insert'], names: ['refund.create'], actorAttribution: 'principal', evidence: 'authoritative' }, mark: async () => { throw new Error('down'); } };
  const watch = skeleton({ observers: [PAYMENTS, AUDIT], turns: [{ id: 'T2', actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { reason: 'watch' } }] });
  const record = await runWatch(watch, { env: { SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B: 'a'.repeat(32) }, factory: () => [witnessed, failing], sleep: async ms => calls.push(`sleep ${ms}`),
    transport: async (origin, request) => { calls.push(`send ${request.method} ${request.path}`); return { status: 201, complete: true }; } });
  assert.deepEqual(calls, ['mark', 'send POST /api/orders/B-1/refunds', 'sleep 500', 'markWitnessRequest n1 {"headSplit":true}', 'send GET /api/egress-witness?scopehaven_witness=n1', 'mark', 'collect n1-n6']);
  assert.deepEqual(record.turns[0].windows.map(w => [w.observer, w.coverage, w.reason]), [['app-payments', 'complete', null], ['app-audit', 'failed', 'observer-not-marked']], 'a failed mark fails only its own window');
});

test('a generated row id that equals a number in the path is not pinned; the object the path names is', () => {
  const draftWith = auditResource => {
    const r = structuredClone(secure.record), turn = r.turns[1], watch = structuredClone(secure.watch);
    turn.path = watch.turns[1].path = '/api/orders/1/refunds';
    turn.windows.find(w => w.observer === 'app-audit').events[0].resource = auditResource;
    const only = draftFromWatch(watch, reseal({ ...r, watchId: watchId(watch) })).profile.targets[0].checks.find(c => c.id === 'WF-T2-ONLY');
    return only.effects[0].expect.map(e => [e.select.source, e.select.resource ?? null]);
  };
  // refunds/1 is a row id the application made: the 1 in the path is the order, so the audit row is counted by name.
  assert.deepEqual(draftWith('refunds/1'), [['sql-audit-table', null], ['http-egress', null]]);
  // orders/1 names the order the request named (type and id as consecutive path segments): pinned.
  assert.deepEqual(draftWith('orders/1'), [['sql-audit-table', 'orders/1'], ['http-egress', null]]);
});

test('an undeclared principal is inferred only from a drafted turn showing exactly one of them', async () => {
  const partial = await watched('secure', { observers: [{ ...AUDIT, principals: ['agent-a'] }] });
  const turnAudit = r => r.turns[1].windows.find(w => w.observer === 'app-audit');
  // Two different undeclared principals wrote in the turn: neither is read as the actor.
  const two = structuredClone(partial.record);
  turnAudit(two).events.push({ ...turnAudit(two).events[0], seq: turnAudit(two).events[0].seq + 1, actor: 'unlisted:0123456789abcdef' });
  assert.throws(() => draftFromWatch(partial.watch, reseal(two)), e => e.notDrafted.some(n => n.turn === 'T2' && n.reason.startsWith('write-by-another-principal')));
  // A turn not drafted (another write names a declared principal) adds no inferred principal to its observer.
  const mixed = structuredClone(partial.record), w = turnAudit(mixed);
  w.events.push({ ...w.events[0], seq: w.events[0].seq + 1, actor: 'agent-a' });
  assert.throws(() => draftFromWatch(partial.watch, reseal(mixed)), /Nothing to draft: T1 no-write-observed, T2 write-by-another-principal/);
});

const authorizationFor = async (dir, origin, untilMs, name) => {
  const now = Date.now(), iso = ms => new Date(ms).toISOString();
  const sealed = checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: `watch-${name}`, target: { id: 'example-watch', applicationId: 'example-support' }, origins: [origin], identities: ['agent-b'],
    validFrom: iso(now - 60000), validUntil: iso(now + untilMs), signer: { name: 'A. Example', role: 'Owner' }, signedAt: iso(now - 60000) });
  const path = join(dir, `${name}.json`); await writeFile(path, JSON.stringify(sealed)); return { path, until: Date.parse(sealed.validUntil) };
};
const fourRefunds = observers => ({ ...skeleton({ observers }), turns: ['T2', 'T3', 'T4', 'T5'].map(id => ({ id, actorId: 'agentB', method: 'POST', path: '/api/orders/B-1/refunds', body: { reason: 'watch' } })) });
const CREDENTIAL = { SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B: 'a'.repeat(32) };

test('the watch CLI checks the window before every request: with no observers, no request starts after it ends', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first requests ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const watch = fourRefunds(undefined); delete watch.target.observers;
  const file = join(dir, 'watch.json'); await writeFile(file, JSON.stringify(watch));
  const { path, until } = await authorizationFor(dir, watch.target.origin, 900, 'requests');
  const starts = [];
  const transport = async () => { starts.push(Date.now()); await new Promise(r => setTimeout(r, 400)); return { status: 201, complete: true }; };
  await assert.rejects(main(['watch', file, '--authorization', path, '--out', join(dir, 'r.json')], { env: CREDENTIAL, log: () => {}, transport }), e => e.code === 'authorization-window-ended');
  assert.ok(starts.length >= 1 && starts.length < 4, `${starts.length} requests`);
  assert.ok(starts.every(at => at < until), 'every request started inside the window');
});

test('the watch CLI checks the window when every observer call starts: none starts after it ends', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven watch-first observers ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const watch = fourRefunds([{ ...AUDIT, settleMs: 400 }]);
  const file = join(dir, 'watch.json'); await writeFile(file, JSON.stringify(watch));
  const { path, until } = await authorizationFor(dir, watch.target.origin, 900, 'observers');
  const calls = [];
  const observerFactory = () => [{ kind: 'sqlite-audit', instanceId: 'sqlite-audit-app-audit', source: 'sql-audit-table', scope: { operations: ['insert'], names: ['refund.create'], actorAttribution: 'principal', evidence: 'authoritative' },
    start: async () => { calls.push(['start', Date.now()]); }, stop: async () => {}, mark: async () => { calls.push(['mark', Date.now()]); return { at: Date.now() }; },
    collect: async () => { calls.push(['collect', Date.now()]); return { events: [], coverage: 'complete', reason: null }; } }];
  await assert.rejects(main(['watch', file, '--authorization', path, '--out', join(dir, 'r.json')], { env: CREDENTIAL, log: () => {}, observerFactory, transport: async () => ({ status: 201, complete: true }) }), e => e.code === 'authorization-window-ended');
  assert.ok(calls.length >= 3);
  assert.deepEqual(calls.filter(([, at]) => at >= until), [], 'no observer call started after the window ended');
});

test('an observer call the window refuses stops the watch: it is never read as a failed observer', async () => {
  let ended = false;
  const check = () => { if (ended) throw new AuthorizationError('authorization-window-ended', 'the window ended'); };
  const fake = { kind: 'sqlite-audit', instanceId: 'sqlite-audit-app-audit', source: 'sql-audit-table', scope: { operations: ['insert'], names: ['refund.create'], actorAttribution: 'principal', evidence: 'authoritative' },
    start: async () => {}, stop: async () => {}, mark: async () => ({ at: 1 }), collect: async () => ({ events: [], coverage: 'complete', reason: null }) };
  const watch = skeleton({ observers: [AUDIT], turns: [TWO[0]] });
  // The window ends while the turn settles: its end mark is the first call refused.
  await assert.rejects(runWatch(watch, { env: CREDENTIAL, factory: guardObserverFactory(() => [fake], check), sleep: async () => {},
    transport: async () => { ended = true; return { status: 201, complete: true }; } }), e => e.code === 'authorization-window-ended');
});

test('split targets keep the validator\'s limits, and a writing check after the drafted lines is warned about', async () => {
  const two = await watched('secure', { turns: TWO });
  const long = structuredClone(two.watch); long.target.id = 'x'.repeat(80); long.target.name = 'n'.repeat(160);
  long.checks.last = [...long.checks.last, { id: 'B-LATE-REFUND', title: 'A late refund', category: 'Allowed use', severity: 'control', actorId: 'agentB', method: 'POST', path: '/api/orders/B-2/refunds', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] }];
  long.requiredControlIds = [...long.requiredControlIds, 'B-LATE-REFUND'];
  const { profile, report } = draftFromWatch(long, reseal({ ...structuredClone(two.record), watchId: watchId(long) }));
  assert.deepEqual(profile.targets.map(t => [t.id.length, t.id.endsWith(t.checks.find(c => c.id.endsWith('-USE')).observed.turn), t.name.length]), [[80, true, 160], [80, true, 160]]);
  assert.equal(new Set(profile.targets.map(t => t.id)).size, 2);
  assert.ok(report.warnings.some(w => w.startsWith('hand-written check B-LATE-REFUND comes after the drafted lines and can commit a write')));
  // More write turns than a profile holds targets: refused with the reason.
  const many = structuredClone(two.watch); many.turns = Array.from({ length: 21 }, (_, i) => ({ ...TWO[0], id: `W${i}` }));
  const manyRecord = reseal({ ...structuredClone(two.record), watchId: watchId(many), turns: many.turns.map(t => ({ ...structuredClone(two.record.turns[0]), id: t.id })) });
  assert.throws(() => draftFromWatch(many, manyRecord), /21 write turns to draft; a profile holds 20 targets/);
});

test('one undeclared principal digest seen under two actors is no one\'s, and an undrafted turn adds no principal', async () => {
  const partial = await watched('secure', { observers: [{ ...AUDIT, principals: ['agent-a'] }], turns: TWO });
  const withC = (edit = () => {}) => {
    const watch = structuredClone(partial.watch), record = structuredClone(partial.record);
    watch.target.actors.agentC = { principalId: 'agent-c', tenantId: 'globex', role: 'agent', credentialEnv: 'SCOPEHAVEN_TARGET_EXAMPLE_AGENT_C', identityValue: 'agent-c@globex.test' };
    watch.turns[1].actorId = record.turns[1].actorId = 'agentC';
    edit(record);
    return [watch, reseal({ ...record, watchId: watchId(watch) })];
  };
  // The same digest wrote in T2 (sent as agent-b) and T3 (sent as agent-c): neither turn is drafted.
  assert.throws(() => draftFromWatch(...withC()), e => e.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]).join() === 'T2,write-by-another-principal,T3,write-by-another-principal');
  // T3 shows another digest beside a declared principal's write: it is not drafted, and agent-c is not inferred from it.
  const [watch, record] = withC(r => { const w = r.turns[1].windows.find(x => x.observer === 'app-audit'); w.events[0].actor = 'unlisted:0123456789abcdef'; w.events.push({ ...w.events[0], seq: w.events[0].seq + 1, actor: 'agent-a' }); });
  const { profile, report } = draftFromWatch(watch, record);
  assert.deepEqual(report.notDrafted.map(n => [n.turn, n.reason.split(':')[0]]), [['T3', 'write-by-another-principal']]);
  assert.deepEqual(profile.targets[0].observers[0].observed.principalsAdded, ['agent-b']);
});

test('an observer start the window refuses still stops every observer that started', async () => {
  const calls = []; let n = 0;
  const check = () => { if (++n > 1) throw new AuthorizationError('authorization-window-ended', 'the window ended'); };
  const fake = id => ({ kind: 'sqlite-audit', instanceId: `sqlite-audit-${id}`, source: 'sql-audit-table', scope: { operations: ['insert'], names: ['refund.create'], actorAttribution: 'principal', evidence: 'authoritative' },
    start: async () => calls.push(`start ${id}`), stop: async () => calls.push(`stop ${id}`), mark: async () => ({}), collect: async () => ({ events: [], coverage: 'complete', reason: null }) });
  const watch = skeleton({ observers: [AUDIT, { ...AUDIT, id: 'app-audit-2' }], turns: [TWO[0]] });
  await assert.rejects(runWatch(watch, { env: CREDENTIAL, factory: guardObserverFactory(() => [fake('a'), fake('b')], check), transport: async () => ({ status: 201, complete: true }) }), e => e.code === 'authorization-window-ended');
  assert.deepEqual(calls, ['start a', 'stop a', 'stop b']);
});
