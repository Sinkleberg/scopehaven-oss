import test from 'node:test';
import assert from 'node:assert/strict';
import { createDashboardAdapter, EXTERNAL_PREVIEW_FORMAT, EXTERNAL_PREVIEW_MAX_BYTES } from './adapter.mjs';

const baseline = '12345678-1234-1234-1234-123456789abc';
const candidate = 'abcdefab-abcd-abcd-abcd-abcdefabcdef';
function mock() {
  const calls = [], result = { ok: true };
  const adapter = createDashboardAdapter({
    request: (...args) => { calls.push(['request', ...args]); return result; },
    download: (...args) => { calls.push(['download', ...args]); return result; },
  });
  return { adapter, calls, result };
}

test('all methods preserve native routes, bodies and callback results', () => {
  const { adapter, calls, result } = mock();
  const invocations = [
    () => adapter.bootstrap(), () => adapter.history(), () => adapter.history('eyJ2IjoxfQ'),
    () => adapter.run(baseline), () => adapter.assess('demo-vulnerable'),
    () => adapter.note(baseline, 'AUTH-01', 'A human observation <script>'),
    () => adapter.compare(baseline, candidate), () => adapter.exportSuite('demo-repaired'),
    () => adapter.exportRun(baseline), () => adapter.exportRun(candidate, 'html'),
    () => adapter.gate(baseline), () => adapter.previewExternal('{"hello":"world"}'),
  ];
  invocations.forEach(invoke => assert.equal(invoke(), result));
  assert.deepEqual(calls, [
    ['request', '/api/bootstrap'], ['request', '/api/history'], ['request', '/api/history?before=eyJ2IjoxfQ'],
    ['request', `/api/runs/${baseline}`], ['request', '/api/runs', { targetId: 'demo-vulnerable' }],
    ['request', `/api/runs/${baseline}/notes`, { caseId: 'AUTH-01', note: 'A human observation <script>' }],
    ['request', `/api/compare?baseline=${baseline}&candidate=${candidate}`],
    ['download', '/api/suite/export.json?targetId=demo-repaired', 'scopehaven-check-definitions.json'],
    ['download', `/api/runs/${baseline}/export.json`, `scopehaven-${baseline}.json`],
    ['download', `/api/runs/${candidate}/report.html`, `scopehaven-${candidate}.html`],
    ['request', `/api/runs/${baseline}/gate`],
    ['request', '/api/external-evaluations/preview', { format: EXTERNAL_PREVIEW_FORMAT, content: '{"hello":"world"}' }],
  ]);
  assert.ok(Object.isFrozen(adapter));
});

test('unsafe identifiers and destinations never reach transport', () => {
  const { adapter, calls } = mock();
  for (const id of ['', null, undefined, 1, '../secret', '%2fsecret', 'https://example.com', baseline + '/notes', baseline + '?access=x']) {
    for (const invoke of [() => adapter.run(id), () => adapter.gate(id), () => adapter.exportRun(id), () => adapter.note(id, 'AUTH-01', ''), () => adapter.compare(id, candidate), () => adapter.compare(baseline, id)]) assert.throws(invoke, { code: 'INVALID_INPUT' });
  }
  for (const id of ['', null, 'x/y', 'x?access=y', '..', 'x'.repeat(81), 'é']) {
    for (const invoke of [() => adapter.assess(id), () => adapter.exportSuite(id), () => adapter.note(baseline, id, '')]) assert.throws(invoke, { status: 400 });
  }
  for (const cursor of ['', null, '../secret', 'abc&limit=1', 'a'.repeat(257)]) assert.throws(() => adapter.history(cursor), { status: 400 });
  for (const format of ['', null, 'pdf', '../../secret', 'https://example.com']) assert.throws(() => adapter.exportRun(baseline, format), { status: 400 });
  assert.throws(() => adapter.note(baseline, 'AUTH-01', 'x'.repeat(5001)), { status: 400 });
  assert.throws(() => adapter.note(baseline, 'AUTH-01', {}), { status: 400 });
  assert.deepEqual(calls, []);
});

test('external preview enforces UTF-8 byte limit including Unicode', () => {
  const { adapter, calls } = mock();
  for (const text of ['x'.repeat(EXTERNAL_PREVIEW_MAX_BYTES), 'é'.repeat(EXTERNAL_PREVIEW_MAX_BYTES / 2), '😀'.repeat(EXTERNAL_PREVIEW_MAX_BYTES / 4)]) adapter.previewExternal(text);
  assert.equal(calls.length, 3);
  for (const text of ['x'.repeat(EXTERNAL_PREVIEW_MAX_BYTES + 1), 'é'.repeat(EXTERNAL_PREVIEW_MAX_BYTES / 2) + 'x', '😀'.repeat(EXTERNAL_PREVIEW_MAX_BYTES / 4) + 'x']) assert.throws(() => adapter.previewExternal(text), { status: 413, code: 'CONTENT_TOO_LARGE' });
  for (const text of ['', ' \n ', null, {}, 123]) assert.throws(() => adapter.previewExternal(text), { status: 400 });
  assert.equal(calls.length, 3);
});

test('authentication and transport failures retain their original identity', async () => {
  const failure = Object.assign(new Error('Unlock required'), { status: 401, code: 'ACCESS_REQUIRED' });
  const adapter = createDashboardAdapter({ request: () => Promise.reject(failure), download: () => Promise.reject(failure) });
  await assert.rejects(adapter.bootstrap(), error => error === failure);
  await assert.rejects(adapter.exportRun(baseline), error => error === failure);
  for (const options of [undefined, {}, { request() {} }, { download() {} }]) assert.throws(() => createDashboardAdapter(options), { code: 'INVALID_INPUT' });
});
