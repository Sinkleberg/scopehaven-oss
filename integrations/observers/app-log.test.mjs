// The app action log reader (integrations/observers/app-log.mjs) and its line mapping (src/app-log-rules.mjs). Temporary files
// only: no socket, no request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, appendFileSync, renameSync, truncateSync, openSync, writeSync, closeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAppLogObserver, startAppLogs } from './app-log.mjs';
import { compileAppLog, readAppLogLine, appLogReason } from '../../src/app-log-rules.mjs';
import { validateWindow } from './events.mjs';

const DECLARED = path => ({ id: 'actions', use: 'record', log: { file: { path } },
  fields: { action: '/event', outcome: '/result', actor: '/who/id', target: '/to', at: '/ts', id: '/id' },
  outcomes: { committed: ['ok', 200], denied: ['refused'], error: ['error'] },
  rules: [
    { action: 'refund.created', operation: 'send', vocabulary: 'egress', name: 'pay.example', resource: 'POST /v1/refunds', observedAs: ['http-egress'] },
    { action: 'email.sent', operation: 'send', vocabulary: 'mail', domains: [{ domain: 'customers.example', addresses: ['vip@customers.example'] }], observedAs: ['provider-feed'] },
    { action: 'order.updated', operation: 'update', vocabulary: 'named', name: 'orders' },
  ],
  ignore: [{ action: 'page.viewed' }],
  logActors: { 'member-1': 'u-1', 'svc-sync': 'system' } });
const TARGET = path => ({ observers: [{ id: 'mailfeed', type: 'provider-feed', witness: { domain: 'witness.scopehaven.invalid' } }], appLogs: [DECLARED(path)] });
const line = entry => `${JSON.stringify(entry)}\n`;

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-app-log-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'actions.jsonl'); writeFileSync(path, line({ id: 0, event: 'refund.created', who: { id: 'u-1' }, result: 'ok' }));
  const cfg = compileAppLog(DECLARED(path), TARGET(path));
  return { path, cfg, reader: createAppLogObserver(cfg, { clock: () => Date.parse('2026-10-13T20:00:00.000Z') }) };
}

test('a line maps to effects in the declared vocabulary, with the actor, outcome and time the log states', t => {
  const { cfg } = setup(t);
  const read = text => readAppLogLine(JSON.stringify(text), cfg);
  assert.deepEqual(read({ event: 'refund.created', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:00Z', id: 7 }).effects,
    [{ actor: 'member-1', operation: 'send', outcome: 'committed', at: '2026-10-13T19:00:00.000Z', name: 'pay.example', resource: 'POST /v1/refunds' }]);
  // Outcome words are type-strict: 200 is committed, "200" is not a declared word.
  assert.equal(read({ event: 'refund.created', who: { id: 'u-1' }, result: 200, ts: '2026-10-13T19:00:00Z' }).effects[0].outcome, 'committed');
  const unmapped = read({ event: 'refund.created', who: { id: 'u-1' }, result: '200', ts: '2026-10-13T19:00:00Z' });
  assert.equal(unmapped.effects[0].outcome, 'unknown'); assert.deepEqual(unmapped.problems, ['app-log-outcome-unmapped']);
  assert.equal(read({ event: 'order.updated', who: { id: 'u-1' }, result: 'refused', ts: '2026-10-13T19:00:00Z' }).effects[0].outcome, 'denied');
  // Actors: a mapped value names its principal, any other value an unlisted digest, none is null.
  assert.equal(read({ event: 'order.updated', who: { id: 'system' }, result: 'ok', ts: '2026-10-13T19:00:00Z' }).effects[0].actor, 'svc-sync');
  assert.match(read({ event: 'order.updated', who: { id: 'u-9' }, result: 'ok', ts: '2026-10-13T19:00:00Z' }).effects[0].actor, /^unlisted:[0-9a-f]{16}$/);
  assert.equal(read({ event: 'order.updated', result: 'ok', ts: '2026-10-13T19:00:00Z' }).effects[0].actor, null);
  assert.deepEqual(read({ event: 'order.updated', result: 'ok', ts: 'yesterday' }).problems, ['app-log-time-unreadable']);
});

test('mail: one send per recipient, named by its domain and a declared address or "*"; witness mail is no effect', t => {
  const { cfg } = setup(t);
  const read = to => readAppLogLine(JSON.stringify({ event: 'email.sent', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:00Z', to }), cfg);
  const two = read(['VIP@Customers.Example.', 'kim@customers.example']);
  assert.deepEqual(two.effects.map(e => [e.name, e.resource]), [['customers.example', 'vip@customers.example'], ['customers.example', '*']]);
  assert.deepEqual(two.problems, []);
  assert.equal(read('n-1@witness.scopehaven.invalid').kind, 'witness');
  assert.deepEqual(read(['n-1@witness.scopehaven.invalid', 'kim@customers.example']).problems, ['app-log-witness-mixed']);
  assert.deepEqual(read('vip+tag@customers.example').problems, ['app-log-recipient-ambiguous']);
  assert.deepEqual(read('"vip"@customers.example').problems, ['app-log-target-unusable']);
  assert.deepEqual(read(42).problems, ['app-log-target-unusable']);
});

test('strict classification: unknown actions and unreadable lines leave the window partial; ignored actions are skipped', t => {
  const { cfg } = setup(t);
  assert.deepEqual(readAppLogLine(JSON.stringify({ event: 'page.viewed' }), cfg), { kind: 'ignored', effects: [], problems: [] });
  assert.deepEqual(readAppLogLine(JSON.stringify({ event: 'refund.voided', result: 'ok' }), cfg).problems, ['app-log-unknown-action']);
  assert.deepEqual(readAppLogLine('{not json', cfg).problems, ['app-log-unreadable-line']);
  assert.deepEqual(readAppLogLine(JSON.stringify(['an', 'array']), cfg).problems, ['app-log-unreadable-line']);
  assert.deepEqual(readAppLogLine(JSON.stringify({ event: 'x'.repeat(70000) }), cfg).problems, ['app-log-unreadable-line']);
});

test('a window is [start mark, cut]: lines before the start and after the cut are not the check\'s', async t => {
  const { path, reader } = setup(t);
  await reader.start();
  appendFileSync(path, line({ id: 1, event: 'refund.created', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:00Z' }));
  const start = reader.mark();
  appendFileSync(path, line({ id: 2, event: 'order.updated', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:01Z' }));
  appendFileSync(path, line({ id: 3, event: 'page.viewed' }));
  const cut = reader.mark();
  appendFileSync(path, line({ id: 4, event: 'refund.created', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:02Z' }));
  const w = validateWindow(reader.collect(start, cut));
  assert.equal(w.source, 'app-log'); assert.equal(w.coverage, 'complete'); assert.equal(w.scope.evidence, 'presence-only');
  assert.deepEqual(w.events.map(e => e.name), ['orders']);
  assert.equal(w.events[0].observer.kind, 'app-action-log');
});

test('a line still being written at the cut is not read and leaves the window partial; a repeated entry id too', async t => {
  const { path, reader } = setup(t);
  await reader.start();
  const start = reader.mark();
  appendFileSync(path, line({ id: 1, event: 'order.updated', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:01Z' }));
  appendFileSync(path, line({ id: 1, event: 'order.updated', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:01Z' }));
  appendFileSync(path, '{"id": 2, "event": "refund.cre');
  const cut = reader.mark();
  const w = reader.collect(start, cut);
  assert.equal(w.coverage, 'partial');
  assert.equal(w.reason, 'app-log-duplicate-id,app-log-line-incomplete-at-cut');
  assert.equal(w.events.length, 2);
});

test('consistency at marks: bytes rewritten below a mark, a truncation or a rotation fail the window', async t => {
  for (const tamper of ['rewrite', 'truncate', 'rotate']) {
    const { path, reader } = setup(t);
    await reader.start();
    const start = reader.mark();
    appendFileSync(path, line({ id: 1, event: 'order.updated', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:01Z' }));
    const cut = reader.mark();
    if (tamper === 'rewrite') { const fd = openSync(path, 'r+'); writeSync(fd, 'X', 2); closeSync(fd); }
    if (tamper === 'truncate') truncateSync(path, 0);
    if (tamper === 'rotate') { renameSync(path, `${path}.1`); writeFileSync(path, ''); }
    const w = reader.collect(start, cut);
    assert.equal(w.coverage, 'failed', tamper);
    assert.equal(w.events.length, 0, tamper);
  }
});

test('a rotation between marks, an unmarked window and a missing file read failed, never thrown', async t => {
  const { path, reader } = setup(t);
  await reader.start();
  renameSync(path, `${path}.1`); writeFileSync(path, '');
  const start = reader.mark(), cut = reader.mark();
  assert.equal(start.rotated, true);
  assert.equal(reader.collect(start, cut).reason, 'app-log-truncated-or-rotated');
  assert.equal(reader.collect(null, cut).coverage, 'failed');
  const missing = createAppLogObserver(compileAppLog(DECLARED(`${path}.none`), TARGET(path)));
  await assert.rejects(missing.start(), /app-log-file-missing/);
});

test('a FIFO or other non-regular file at the path reads failed at once, never blocking the run', async t => {
  const { path } = setup(t);
  const fifo = `${path}.fifo`;
  execFileSync('mkfifo', [fifo]);
  const reader = createAppLogObserver(compileAppLog(DECLARED(fifo), TARGET(fifo)));
  const started = Date.now();
  await assert.rejects(reader.start(), /app-log-file-missing/);
  assert.equal(reader.mark().ok, false);
  assert.ok(Date.now() - started < 2000, 'no blocking open');
});

test('a line already being written at the start mark is never the check\'s: skipped, and the window reads partial', async t => {
  const { path, reader } = setup(t);
  await reader.start();
  appendFileSync(path, '{"id": 9, "event": "order.upd');
  const start = reader.mark();
  appendFileSync(path, 'ated", "who": { "id": "u-1" }, "result": "ok", "ts": "2026-10-13T19:00:00Z" }\n');
  appendFileSync(path, line({ id: 10, event: 'refund.created', who: { id: 'u-1' }, result: 'ok', ts: '2026-10-13T19:00:01Z' }));
  const w = reader.collect(start, reader.mark());
  assert.equal(w.reason, 'app-log-line-incomplete-at-start');
  assert.deepEqual(w.events.map(e => e.name), ['pay.example']);
});

test('an actor the map does not name is kept only as a digest keyed per run', t => {
  const { path } = setup(t);
  const read = cfg => readAppLogLine(JSON.stringify({ event: 'order.updated', who: { id: 'stranger@customers.example' }, result: 'ok', ts: '2026-10-13T19:00:00Z' }), cfg).effects[0].actor;
  const one = compileAppLog(DECLARED(path), TARGET(path)), two = compileAppLog(DECLARED(path), TARGET(path));
  assert.match(read(one), /^unlisted:[0-9a-f]{16}$/);
  assert.equal(read(one), read(one), 'stable within a run');
  assert.notEqual(read(one), read(two), 'keyed: another run cannot match it');
});

test('startAppLogs: a log that cannot start gives failed windows and never throws into a check', async t => {
  const { path } = setup(t);
  const logs = await startAppLogs({ ...TARGET(path), appLogs: [DECLARED(`${path}.none`)] });
  const w = logs.collect(logs.mark(), logs.mark());
  assert.equal(w.length, 1); assert.equal(w[0].coverage, 'failed'); assert.equal(w[0].reason, 'app-log-not-started');
  await logs.stop();
});

test('a window reason keeps whole codes within the 200-character limit', () => {
  const codes = ['app-log-duplicate-id', 'app-log-line-incomplete-at-cut', 'app-log-outcome-unmapped', 'app-log-recipient-ambiguous', 'app-log-target-unusable', 'app-log-time-unreadable', 'app-log-unknown-action', 'app-log-unreadable-line', 'app-log-witness-mixed'];
  const reason = appLogReason(codes);
  assert.ok(reason.length <= 200);
  assert.ok(reason.split(',').every(code => codes.includes(code)));
  assert.equal(appLogReason([]), null);
});
