// Resource bounds on target-supplied observer input (self security change scan, 2026-10-06):
// an audit-log URI full of '?' cannot make classification quadratic, and the OTLP receiver
// cannot be made to retain unbounded raw span values.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtempSync, writeFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createAuditFileObserver, AUDIT_FILE_MAX_QUERY_CUTS } from './audit-file.mjs';
import { createOtelObserver } from './otel.mjs';

const auditLine = uri => JSON.stringify({ verb: 'GET', request_uri: `http://127.0.0.1:9${uri}`, response_status_code: 200, user: { id: 'u1' } }) + '\n';
async function auditWindow(text) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-bounds-')), log = join(dir, 'audit.log');
  try {
    writeFileSync(log, '');
    const o = createAuditFileObserver({ path: log, origin: 'http://127.0.0.1:9', witness: 'read', settleMs: 0, quietMs: 100, rules: [{ name: 'read', method: 'GET', path: '/api/items/{id}' }] });
    await o.start(); const from = await o.mark();
    appendFileSync(log, text);
    const to = await o.mark(), t0 = performance.now();
    return { window: await o.collect(from, to), ms: performance.now() - t0 };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('an audit URI with more than the allowed number of "?" is ambiguous, and classifying it stays fast', async () => {
  const { window, ms } = await auditWindow(auditLine(`/x${'?'.repeat(16000)}`).repeat(8));
  assert.equal(window.coverage, 'partial');
  assert.match(window.reason, /ambiguous-audit-line/);
  assert.ok(ms < 1500, `collect took ${ms.toFixed(0)} ms`);
});

test('an audit URI within the "?" allowance is still read as before', async () => {
  const { window } = await auditWindow(auditLine(`/api/items/7${'?'.repeat(AUDIT_FILE_MAX_QUERY_CUTS - 1)}`));
  assert.doesNotMatch(window.reason ?? '', /ambiguous-audit-line/);
  assert.equal(window.events.length, 1);
});

const post = (url, body) => new Promise((resolve, reject) => {
  const payload = Buffer.from(JSON.stringify(body));
  const r = request(url, { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  r.on('error', reject); r.end(payload);
});
const toolSpanAt = (spanId, at, args) => ({ traceId: '1'.repeat(32), spanId, name: 'execute_tool t', startTimeUnixNano: String(at), endTimeUnixNano: String(at + 1n),
  attributes: [{ key: 'gen_ai.operation.name', value: { stringValue: 'execute_tool' } }, { key: 'gen_ai.tool.call.arguments', value: { stringValue: args } }] });
const otlp = spans => ({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'app' } }] }, scopeSpans: [{ spans }] }] });

test('the OTLP receiver stops retaining tool spans past its character budget and reports the window partial', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50, maxRetainedChars: 1000 }); await o.start();
  try {
    const from = await o.mark();
    assert.equal(await post(o.endpoint, otlp([toolSpanAt('2222222222222222', from.at + 1n, 'a'.repeat(600))])), 200);
    assert.equal(await post(o.endpoint, otlp([toolSpanAt('3333333333333333', from.at + 2n, 'b'.repeat(600))])), 200);
    const to = await o.mark(), w = await o.collect(from, to);
    assert.equal(w.events.length, 1, 'the span past the budget is not retained');
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'span-limit-reached');
  } finally { await o.stop(); }
});
