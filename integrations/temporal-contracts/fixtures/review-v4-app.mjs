// The lead's two v3b probes over the existing app and real loopback provider.
// The gap hook runs between collector operations, avoiding a timer/mark race.
import { createServer, request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';
import { bearer, body, json, localHostAllowed } from '../../../src/http.mjs';
import { observeHttp } from '../../../src/http-connector.mjs';
import { startRefundFixture } from './refund-app.mjs';

export async function startReviewFixture({ mode = 'honest', log = [], ...config } = {}) {
  if (!['honest', 'mid-gap', 'predict-late'].includes(mode)) throw new Error('Unknown review fixture mode.');
  const app = await startRefundFixture(config), authorities = new Map();
  let horizon, gap, proxy;
  function authorize(authority) {
    const binding = app.authorize(authority); authorities.set(binding.instructionId, binding); return binding;
  }
  async function snapshot(options) {
    horizon = options;
    const value = structuredClone(await app.snapshot(options));
    if (!gap) return value;
    // The decorator is part of this synthetic app's ledger. Keep its extra
    // dispatch and all following sequence references consistent on both reads.
    value.events.splice(gap.afterSeq, 0, gap.event);
    value.events = value.events.map((event, index) => ({ ...event, seq: index + 1 }));
    const shifted = seq => seq > gap.afterSeq ? seq + 1 : seq;
    for (const instruction of value.instructions) {
      instruction.acceptanceSeq = shifted(instruction.acceptanceSeq);
      if (instruction.terminal) instruction.terminal.seq = shifted(instruction.terminal.seq);
      if (instruction.instructionId === 'revoked-new') instruction.attemptIds.push(gap.event.attemptId);
    }
    value.horizon.watermark++; value.coverage.toSeq++;
    return value;
  }
  async function sendGapRefund() {
    if (mode !== 'mid-gap' || gap || !horizon || horizon.close) throw new Error('Invalid gap dispatch state.');
    const before = await app.snapshot({ ...horizon, close: false }), binding = authorities.get('revoked-new');
    if (!before.events.some(event => event.type === 'refused' && event.instructionId === 'revoked-new')) throw new Error('Gap dispatch requires the completed refusal.');
    const attemptId = randomUUID();
    gap = { afterSeq: before.horizon.watermark, event: { type: 'attempt', atMs: before.events.at(-1).atMs,
      attemptId, instructionId: binding.instructionId, principalId: binding.principalId,
      authorityId: binding.authorityId, binding } };
    const payload = Buffer.from(JSON.stringify({ charge: binding.chargeId, amount: binding.amount, currency: binding.currency, destination: binding.destination }));
    const response = await new Promise((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port: config.payments.port, method: 'POST', path: '/pay/v1/refunds',
        headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length,
          'X-Scopehaven-Run': config.runId, 'X-Scopehaven-Instruction': binding.instructionId,
          'X-Scopehaven-Attempt': attemptId, 'X-Scopehaven-Authority': binding.authorityId,
          'X-Scopehaven-Principal': binding.principalId, 'X-Scopehaven-Tenant': binding.tenantId,
          'X-Scopehaven-Currency': binding.currency, 'Idempotency-Key': `review-gap-${config.runId}` } }, res => {
        const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch (error) { reject(error); } });
      });
      req.on('error', reject); req.setTimeout(2000, () => req.destroy(new Error('Local gap refund timed out.'))); req.end(payload);
    });
    log.push({ midGapSend: true, attemptId, status: response.status, effectId: response.body.id });
    return response;
  }
  async function release(instructionId) {
    if (mode === 'predict-late' && instructionId === 'pre-cutoff') await wait(5200);
    return app.release(instructionId);
  }
  // Only the predicted reply differs from the app's normal HTTP response. Its
  // pending job, later dispatch, final state and ledger remain the real app's.
  if (mode === 'predict-late') {
    proxy = createServer(async (req, res) => {
      try {
        if (!localHostAllowed(req, proxy.address()) || req.headers.origin !== undefined || req.headers['sec-fetch-site'] !== undefined) return json(res, 403, { error: 'Local non-browser requests only.' });
        const input = req.method === 'POST' ? await body(req, 8192) : undefined;
        const response = await observeHttp(app.origin, { method: req.method, path: req.url, ...(input === undefined ? {} : { body: input }) }, { credential: bearer(req) });
        if (!response.complete) return json(res, 502, { error: 'Local fixture response unavailable.' });
        if (input?.instructionId === 'pre-cutoff' && input.hold === 'after-acceptance' && response.status === 202) {
          const effectId = `re_test_${String(config.payments.providerLedger().refunds.length + 1).padStart(6, '0')}`;
          log.push({ predictedReply: effectId });
          return json(res, 200, { instructionId: input.instructionId, state: 'success', effectId });
        }
        return json(res, response.status, response.json);
      } catch (error) { if (!res.headersSent && !res.destroyed) json(res, error.status ?? 500, { error: 'Review fixture request failed.' }); }
    });
    proxy.requestTimeout = 3000; proxy.headersTimeout = 3000;
    try { await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); }); }
    catch (error) { await app.close(); throw error; }
  }
  async function close() {
    if (proxy) await new Promise(resolve => { proxy.close(resolve); proxy.closeAllConnections(); });
    await app.close();
  }
  return Object.freeze({ ...app, origin: proxy ? `http://127.0.0.1:${proxy.address().port}` : app.origin,
    authorize, release, snapshot, close, sendGapRefund });
}
