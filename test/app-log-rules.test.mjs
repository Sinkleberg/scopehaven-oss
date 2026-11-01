// App log declarations (src/app-log-rules.mjs), checked when a profile is validated, before any request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { validateTargetFile, contractDigest } from '../src/contracts.mjs';
import { appLogRecords, validAppLogRecords, APP_LOG_COLLECTOR } from '../src/app-log-verdicts.mjs';

const LOG = (extra = {}) => ({ id: 'actions', use: 'record', log: { file: { path: '/srv/app/actions.jsonl' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', target: '/to' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [{ action: 'refund.created', operation: 'send', vocabulary: 'egress', name: 'pay.example', resource: 'POST /v1/refunds', observedAs: ['http-egress'] },
    { action: 'email.sent', operation: 'send', vocabulary: 'mail', domains: [{ domain: 'customers.example' }] },
    { action: 'order.updated', operation: 'update', vocabulary: 'named', name: 'orders', resource: 'GLX-2002' }],
  logActors: { 'member-1': 'u-1' }, ...extra });
const target = (extra = {}) => ({ id: 'app', name: 'App', applicationId: 'app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'c1',
  actors: { member: { principalId: 'member-1' }, ops: { principalId: 'ops-1' } }, requiredControlIds: ['WHOAMI'],
  checks: [{ id: 'WHOAMI', title: 'whoami', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }],
  appLogs: [LOG()], ...extra });
const valid = t => validateTargetFile({ schemaVersion: 1, targets: [t] })[0];
const refused = (t, pattern, label) => assert.throws(() => valid(t), pattern, label);

test('a declared app log validates, enters the profile digest, and leaves undeclared profiles\' digests unchanged', () => {
  const declared = valid(target());
  const { appLogs, ...undeclared } = target();
  assert.notEqual(contractDigest(declared), contractDigest(valid(undeclared)));
  // The key is absent, never null, so an undeclared profile digests exactly as before.
  assert.equal(Object.hasOwn(valid(undeclared), 'appLogs'), false);
  const records = appLogRecords(declared.appLogs);
  assert.ok(validAppLogRecords(records));
  assert.deepEqual(Object.keys(records[0]).sort(), ['collector', 'id', 'mappingDigest', 'principals', 'projection', 'reads', 'route', 'scope', 'use']);
  assert.equal(JSON.stringify(records).includes('/srv/app'), false, 'the file path stays local');
  assert.equal(records[0].collector, APP_LOG_COLLECTOR);
});

test('refused at load: an undeclared or later use, later-version keys, and shapes the reader cannot read', () => {
  const { use, ...noUse } = LOG();
  refused(target({ appLogs: [noUse] }), /"use" must be declared/, 'no default use');
  refused(target({ appLogs: [LOG({ use: 'admission+report' })] }), /"use" must be declared and be one of record, admission/, 'there is no use that passes on the log');
  for (const key of ['cause', 'job', 'jobs', 'witness', 'canaries']) refused(target({ appLogs: [LOG({ [key]: {} })] }), new RegExp(`"${key}" is not supported`), key);
  refused(target({ appLogs: [LOG({ log: { endpoint: { port: 4000, path: '/log' } } })] }), /"endpoint" is not supported/, 'the endpoint route');
  refused(target({ appLogs: [LOG(), { ...LOG(), id: 'second' }] }), /exactly one app log/, 'two logs');
  refused(target({ appLogs: [LOG({ log: { file: { path: 'relative.jsonl' } } })] }), /absolute path/);
  refused(target({ appLogs: [LOG({ fields: { action: '/event', actor: '/actor' } })] }), /at least "action" and "outcome"/);
  refused(target({ appLogs: [LOG({ fields: { action: '/event', outcome: '/result', actor: '/actor' } })] }), /a mail rule reads its recipients from "fields.target"/);
  refused(target({ appLogs: [LOG({ rules: [{ action: 'x', operation: 'send', vocabulary: 'egress', name: 'pay.example', resource: '/v1/refunds' }] })] }), /"<METHOD> <declared path>"/);
  refused(target({ appLogs: [LOG({ rules: [{ action: 'x', operation: 'send', vocabulary: 'named', name: 'n' }, { action: 'x', operation: 'send', vocabulary: 'named', name: 'm' }] })] }), /unique "action"/);
  refused(target({ appLogs: [LOG({ rules: [{ action: 'x', operation: 'send', vocabulary: 'named', name: 'n', observedAs: ['http-egress'] }] })] }), /"observedAs" lists the sources that also see this action \(sql-snapshot/);
  refused(target({ appLogs: [LOG({ ignore: [{ action: 'refund.created' }] })] }), /never a mapped action/);
  refused(target({ appLogs: [LOG({ outcomes: { committed: ['ok'], error: ['ok'] } })] }), /listed once/);
  // Names fit the 128-character scope limit, so every window the reader seals validates.
  const longHost = `${'a'.repeat(60)}.${'b'.repeat(60)}.example`;
  refused(target({ appLogs: [LOG({ rules: [{ action: 'x', operation: 'send', vocabulary: 'egress', name: longHost, resource: 'POST *' }] })] }), /at most 128 characters/, 'a long host');
  refused(target({ appLogs: [LOG({ rules: [{ action: 'x', operation: 'send', vocabulary: 'mail', domains: [{ domain: longHost }] }] })] }), /at most 128 characters/, 'a long mail domain');
});

test('refused at load: an actor map that is not one to one, names no checking actor, or cannot tell a background source apart', () => {
  // Mutation target: accept a many-to-one logActors.
  refused(target({ appLogs: [LOG({ logActors: { 'member-1': 'u-1', 'ops-1': 'u-1' } })] }), /one to one/, 'two principals, one log value');
  refused(target({ appLogs: [LOG({ logActors: { 'someone-else': 'u-1' } })] }), /principals of declared actors/);
  refused(target({ appLogs: [LOG({ logActors: { 'ops-1': 'u-9' } })] }), /names no principal of an actor that runs a check/);
  const { actor, ...fields } = LOG().fields;
  refused(target({ appLogs: [LOG({ fields })] }), /"fields.actor" is required/);
  // A background source pinned to the checking actor's principal leaves nothing to separate.
  const observers = [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: 'pay.example', paths: ['/v1/refunds'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250 }];
  const checks = [...target().checks, { id: 'PAY', title: 'pay', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/pay', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: 'pay.example' } }] }];
  refused(target({ observers, checks, attribution: { background: [{ id: 'sync', select: { actor: 'member-1', operation: 'send', name: 'pay.example' } }] } }), /a background source names the principal of an actor that runs a check/);
  valid(target({ observers, checks, attribution: { background: [{ id: 'sync', select: { actor: 'svc-sync', operation: 'send', name: 'pay.example' } }] } }));
});

test('no declared selector may name the app-log source: nothing judges it in this version', () => {
  const checks = [...target().checks, { id: 'PAY', title: 'pay', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/pay', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }],
    effects: [{ kind: 'effect.none', select: { source: 'app-log', operation: 'send', name: 'pay.example' } }] }];
  refused({ ...target({ checks }), observers: [] }, /selector-source-report-only/);
});

test('refused at load: a file another observer reads as the app\'s request log or a provider\'s record', () => {
  const path = '/srv/app/actions.jsonl';
  refused(target({ observers: [{ id: 'reqlog', type: 'audit-file', path, origin: 'http://127.0.0.1:9', rules: [{ name: 'me', method: 'GET', path: '/me' }], witness: { rule: 'me', actorId: 'member', method: 'GET', path: '/me' }, settleMs: 250 }] }), /audit-file observer's log/);
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const feed = { id: 'mailfeed', type: 'provider-feed', feedId: 'mail', feed: { file: { path } }, publicKey, domains: [{ domain: 'customers.example' }], settleMs: 250 };
  refused(target({ observers: [feed] }), /a provider feed's file/);
  valid(target({ observers: [{ ...feed, feed: { file: { path: '/srv/provider/feed.jsonl' } } }] }));
});
