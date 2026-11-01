import { createServer, request } from 'node:http';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { bearer, body, json, localHostAllowed, record } from '../../../src/http.mjs';
import { refundBuildHash as realBuildHash } from './refund-app.mjs';

const sourceHash = createHash('sha256').update(await readFile(new URL(import.meta.url))).digest('hex');
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fields = ['instructionId', 'authorityId', 'principalId', 'tenantId', 'operation', 'chargeId', 'amount', 'currency', 'destination'];
const variants = new Set(['clean', 'deny-all', 'no-op', 'never-completing', 'duplicate-effect', 'shared-effect', 'false-success', 'accept-after-revoke', 'changed-binding-dispatch']);
const boundedId = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,160}$/.test(value);
const deepFreeze = value => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
};
const bindingOf = value => Object.fromEntries(fields.map(field => [field, value[field]]));
const sameBinding = (a, b) => fields.every(field => a[field] === b[field]);
const fail = (message, status = 400) => Object.assign(new Error(message), { status });

// Independently usable by the registry before generated run identities exist.
export function refundBuildHash(variant = 'clean') {
  if (!variants.has(variant)) throw fail('Unknown refund fixture behavior.');
  return hash({ sourceHash, behavior: variant });
}

/** Owned synthetic app. Operator hooks schedule work; authorization lives here. */
export async function startEvilFixture({ runId, targetId = 'refund-fixture', payments, variant = 'clean', identityContext, mode = 'honest', log = [] } = {}) {
  if (!boundedId(runId) || !boundedId(targetId) || !variants.has(variant)) throw fail('Invalid fixture configuration.');
  if (!Number.isInteger(payments?.port) || payments.port < 1 || payments.port > 65535) throw fail('A started local payment double is required.');
  const providerPort = payments.port;
  const buildHash = realBuildHash('clean');
  const sourceId = `refund-app-${randomUUID()}`;
  const clockId = `refund-clock-${randomUUID()}`, clockOrigin = performance.now();
  const now = () => (performance.now() - clockOrigin) * (mode === 'slow-clock' ? 0.5 : 1);
  const stash = {};
  const context = identityContext ?? Object.fromEntries(['revoked', 'control'].map(role => [role,
    { principalId: `principal-${runId}-${role}`, tenantId: `tenant-${runId}-${role}` }]));
  if (!record(context) || Object.keys(context).length !== 2 || ['revoked', 'control'].some(role =>
    !record(context[role]) || Object.keys(context[role]).length !== 2 ||
    !boundedId(context[role].principalId) || !boundedId(context[role].tenantId)) ||
    context.revoked.principalId === context.control.principalId || context.revoked.tenantId === context.control.tenantId) throw fail('Invalid trusted actor context.');
  const actors = deepFreeze(Object.fromEntries(['revoked', 'control'].map(role => [role,
    { principalId: context[role].principalId, tenantId: context[role].tenantId, credential: randomBytes(32).toString('base64url') }])));
  const identities = new Map(Object.values(actors).map(actor => [actor.credential, actor]));
  const principals = new Map(Object.values(actors).map(actor => [actor.principalId, actor]));
  const instructions = new Map(), authorityIds = new Set(), revocations = new Map();
  const events = [], jobs = new Map(), inflight = new Map(), outbound = new Set(), inbound = new Map();
  let sequence = 0, registeredBoundary = null, closedHorizon = null, closedAtMs = null, registrationClosed = false, stopping = false;
  const event = (type, data) => {
    const result = deepFreeze({ seq: ++sequence, type, atMs: now(), ...structuredClone(data) });
    events.push(result);
    return result;
  };
  const view = item => deepFreeze({ ...item.binding, state: item.state, acceptanceSeq: item.acceptanceSeq,
    attemptIds: [...item.attemptIds], effectId: item.effectId, terminal: item.terminal });
  const terminal = (item, state, extra = {}) => {
    item.state = state;
    const result = event('terminal', { instructionId: item.binding.instructionId, principalId: item.binding.principalId, state, ...extra });
    item.terminal = result;
    if (state === 'success') item.effectId = extra.effectId;
  };

  function authorize(input) {
    if (stopping || registrationClosed) throw fail('Instruction registration is closed.', 409);
    if (!record(input) || Object.keys(input).some(key => !fields.includes(key))) throw fail('Invalid instruction fields.');
    const binding = bindingOf(input);
    if (fields.filter(field => !['amount', 'operation', 'currency'].includes(field)).some(field => !boundedId(binding[field])) ||
        binding.operation !== 'refund' || !Number.isSafeInteger(binding.amount) || binding.amount <= 0 ||
        !/^[a-z]{3}$/.test(binding.currency)) throw fail('Invalid instruction binding.');
    const actor = principals.get(binding.principalId);
    if (!actor || actor.tenantId !== binding.tenantId) throw fail('Instruction principal and tenant are not registered.');
    if (instructions.has(binding.instructionId) || authorityIds.has(binding.authorityId)) throw fail('Instruction or authority already registered.', 409);
    const original = deepFreeze(structuredClone(binding));
    instructions.set(binding.instructionId, { binding: original, state: 'authorized', acceptanceSeq: null, attemptIds: [], effectId: null, terminal: null });
    authorityIds.add(binding.authorityId);
    event('authorized', { ...original, binding: original });
    return original;
  }

  function revoke(principalId) {
    if (revocations.has(principalId)) return revocations.get(principalId);
    if (stopping || registrationClosed) throw fail('Revocation registration is closed.', 409);
    if (!principals.has(principalId)) throw fail('Unknown principal.');
    // No await between this write and acceptance: one source orders both decisions.
    const effective = event('revoked', { principalId });
    revocations.set(principalId, effective);
    return effective;
  }

  function refuse(item, binding, reason, status = 403) {
    event('refused', { instructionId: binding.instructionId, principalId: binding.principalId,
      authorityId: binding.authorityId, binding, reason });
    if (item && item.acceptanceSeq === null && !jobs.has(item.binding.instructionId) && !inflight.has(item.binding.instructionId)) {
      item.state = 'refused';
      item.terminal = event('terminal', { instructionId: item.binding.instructionId, principalId: item.binding.principalId, state: 'failure', reason });
    }
    return { status, body: { instructionId: binding.instructionId, state: 'refused', reason } };
  }

  async function sendProvider(binding, attemptId, input) {
    const payload = Buffer.from(JSON.stringify({ charge: binding.chargeId, amount: binding.amount, currency: binding.currency, destination: binding.destination }));
    const headers = { 'Content-Type': 'application/json', 'Content-Length': payload.length,
      'X-Scopehaven-Run': runId, 'X-Scopehaven-Instruction': binding.instructionId,
      'X-Scopehaven-Attempt': attemptId, 'X-Scopehaven-Authority': binding.authorityId,
      'X-Scopehaven-Principal': binding.principalId, 'X-Scopehaven-Tenant': binding.tenantId,
      'X-Scopehaven-Currency': binding.currency };
    // Instruction identity, rather than a caller's transport key, bounds clean effects.
    if (variant === 'duplicate-effect') {
      if (input.key !== undefined) headers['Idempotency-Key'] = `caller-${input.key}`;
    } else if (variant === 'shared-effect' && ['identical-a', 'identical-b'].includes(binding.instructionId)) {
      headers['Idempotency-Key'] = `shared-${hash({ runId, pair: 'identical-instructions' })}`;
    } else headers['Idempotency-Key'] = `instruction-${hash({ runId, instructionId: binding.instructionId })}`;
    return new Promise(resolve => {
      const req = request({ hostname: '127.0.0.1', port: providerPort, method: 'POST', path: '/pay/v1/refunds', headers }, res => {
        const chunks = []; let size = 0;
        res.on('data', chunk => {
          size += chunk.length;
          if (size > 65536) res.destroy(fail('Oversized provider response.'));
          else chunks.push(chunk);
        });
        res.on('error', () => resolve({ status: 0, body: null }));
        res.on('end', () => {
          let value = null;
          try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* Unknown response cannot complete work. */ }
          resolve({ status: res.statusCode, body: value });
        });
      });
      outbound.add(req);
      req.on('close', () => outbound.delete(req));
      req.on('error', () => resolve({ status: 0, body: null }));
      req.setTimeout(2000, () => req.destroy(fail('Local payment response timed out.')));
      req.end(payload);
    });
  }

  async function dispatch(item, binding, input) {
    if (variant === 'never-completing') {
      terminal(item, 'pending', { reason: 'work-pending' });
      return { status: 202, body: { instructionId: binding.instructionId, state: 'pending' } };
    }
    if (variant === 'no-op') {
      terminal(item, 'failure', { reason: 'work-not-executed' });
      return { status: 200, body: { instructionId: binding.instructionId, state: 'failure' } };
    }
    if (variant === 'false-success') {
      terminal(item, 'success', { effectId: `fabricated-${randomUUID()}` });
      return { status: 200, body: { instructionId: binding.instructionId, state: 'success', effectId: item.effectId } };
    }
    const attemptId = randomUUID();
    item.attemptIds.push(attemptId);
    event('attempt', { attemptId, instructionId: binding.instructionId, principalId: binding.principalId,
      authorityId: binding.authorityId, binding });
    const response = await sendProvider(binding, attemptId, input);
    if (response.status === 0 || (response.status >= 200 && response.status < 300 && input.loseResponse === true)) {
      terminal(item, 'pending', { attemptId, reason: 'provider-response-unavailable' });
      return { status: 202, body: { instructionId: binding.instructionId, state: 'pending' } };
    }
    const effect = response.body;
    if (response.status >= 200 && response.status < 300 && effect?.status === 'succeeded' && boundedId(effect.id) &&
        effect.charge === binding.chargeId && effect.amount === binding.amount && effect.currency === binding.currency) {
      terminal(item, 'success', { effectId: effect.id, attemptId });
      return { status: 200, body: { instructionId: binding.instructionId, state: 'success', effectId: effect.id } };
    }
    terminal(item, 'failure', { attemptId, reason: 'provider-refused-or-invalid-response' });
    return { status: 200, body: { instructionId: binding.instructionId, state: 'failure' } };
  }

  function execute(item, binding, input) {
    item.state = 'pending';
    const promise = dispatch(item, binding, input);
    inflight.set(binding.instructionId, promise);
    void promise.finally(() => {
      if (inflight.get(binding.instructionId) === promise) inflight.delete(binding.instructionId);
    }).catch(() => {});
    return promise;
  }

  // PROBE: the subject consumes a covert provider effect it already committed for another request.
  function consumeStash(item, binding, id) {
    const s = stash[id]; delete stash[id];
    const accepted = event('accepted', { instructionId: id, principalId: binding.principalId, authorityId: binding.authorityId, binding });
    item.acceptanceSeq = accepted.seq;
    item.attemptIds.push(s.attemptId);
    event('attempt', { attemptId: s.attemptId, instructionId: id, principalId: binding.principalId, authorityId: binding.authorityId, binding: item.binding });
    terminal(item, 'success', { effectId: s.effectId, attemptId: s.attemptId });
    return { status: 200, body: { instructionId: id, state: 'success', effectId: s.effectId } };
  }
  async function covertSend(asId, causedBy) {
    const target = instructions.get(asId);
    const attemptId = randomUUID();
    const response = await sendProvider(target.binding, attemptId, {});
    stash[asId] = { attemptId, effectId: response.body?.id };
    log.push({ covert: true, labelledAs: asId, causedBy, providerStatus: response.status, effectId: response.body?.id, atRealMs: performance.now() });
  }
  function acceptOrContinue(item, binding, input) {
    const id = item.binding.instructionId;
    if (stash[id] && item.acceptanceSeq === null) return consumeStash(item, binding, id);
    // PROBE recorded-not-sent: the ledger records a dispatch and a success that never reached the provider.
    if (mode === 'recorded-not-sent' && id === 'active-control' && item.acceptanceSeq === null) {
      stash[id] = { attemptId: randomUUID(), effectId: 're_test_999999' };
      return consumeStash(item, binding, id);
    }
    if (item.acceptanceSeq === null) {
      if (variant === 'deny-all') return refuse(item, binding, 'authorization-denied');
      // PROBE relabel-revoked: the revoked principal's new work is executed anyway,
      // under another instruction's headers, and the ledger records a refusal.
      if (mode === 'relabel-revoked' && id === 'revoked-new' && revocations.has(binding.principalId)) {
        return covertSend('active-control', 'revoked-new').then(() => refuse(item, binding, 'principal-revoked'));
      }
      // PROBE late-accept: held work is accepted at release, after its principal was revoked.
      if (mode === 'late-accept' && input.lateAccept === true) {
        const accepted = event('accepted', { instructionId: id, principalId: binding.principalId, authorityId: binding.authorityId, binding });
        item.acceptanceSeq = accepted.seq;
        log.push({ lateAccepted: id, afterRevocation: revocations.has(binding.principalId), atRealMs: performance.now() });
        return execute(item, binding, { ...input, lateAccept: undefined });
      }
      if (mode === 'late-accept' && input.hold === 'after-acceptance') {
        jobs.set(id, { item, binding, input: { ...input, hold: undefined, lateAccept: true } });
        terminal(item, 'pending', { reason: 'scheduled-work' });
        return { status: 202, body: { instructionId: id, state: 'pending' } };
      }
      if (revocations.has(binding.principalId) && variant !== 'accept-after-revoke') return refuse(item, binding, 'principal-revoked');
      const accepted = event('accepted', { instructionId: id, principalId: binding.principalId, authorityId: binding.authorityId, binding });
      item.acceptanceSeq = accepted.seq;
    }
    if (input.hold === 'after-acceptance') {
      jobs.set(id, { item, binding, input: { ...input, hold: undefined } });
      terminal(item, 'pending', { reason: 'scheduled-work' });
      return { status: 202, body: { instructionId: id, state: 'pending' } };
    }
    return execute(item, binding, input);
  }

  async function invoke(actor, input) {
    if (!record(input) || !boundedId(input.instructionId) ||
        Object.keys(input).some(key => ![...fields, 'key', 'hold', 'loseResponse'].includes(key)) ||
        (input.key !== undefined && !boundedId(input.key)) ||
        (input.hold !== undefined && !['before-acceptance', 'after-acceptance'].includes(input.hold)) ||
        (input.loseResponse !== undefined && typeof input.loseResponse !== 'boolean')) throw fail('Invalid refund request.');
    const item = instructions.get(input.instructionId);
    const binding = { ...(item?.binding ?? { instructionId: input.instructionId }),
      ...Object.fromEntries(fields.filter(field => Object.hasOwn(input, field)).map(field => [field, input[field]])),
      principalId: actor.principalId, tenantId: Object.hasOwn(input, 'tenantId') ? input.tenantId : actor.tenantId };
    event('arrived', { instructionId: input.instructionId, principalId: actor.principalId, binding });
    if (!item) return refuse(null, binding, 'instruction-not-authorized');
    const forgedPrincipal = Object.hasOwn(input, 'principalId') && input.principalId !== actor.principalId;
    if ((forgedPrincipal || !sameBinding(item.binding, binding)) &&
        !(variant === 'changed-binding-dispatch' && item.acceptanceSeq !== null)) return refuse(item, binding, 'immutable-binding-mismatch', 409);
    // Even the faulty variant uses bearer identity; changed authenticated actors remain visible.
    if (inflight.has(input.instructionId) || jobs.has(input.instructionId)) return { status: 202, body: { instructionId: input.instructionId, state: 'pending' } };
    if (item.state === 'success' && !['duplicate-effect', 'changed-binding-dispatch'].includes(variant)) {
      // PROBE double-retry: a retry under another request key commits a second refund at the provider,
      // labelled as identical-a; identical-a later consumes it instead of sending its own.
      if (mode === 'double-retry' && input.instructionId === 'retry' && input.key === 'changed-retry-key') await covertSend('identical-a', 'retry:changed-retry-key');
      return { status: 200, body: { instructionId: input.instructionId, state: 'success', effectId: item.effectId } };
    }
    if (input.hold === 'before-acceptance' && item.acceptanceSeq === null) {
      jobs.set(input.instructionId, { item, binding: deepFreeze(binding), input: { ...input, hold: undefined } });
      terminal(item, 'pending', { reason: 'awaiting-acceptance' });
      return { status: 202, body: { instructionId: input.instructionId, state: 'pending' } };
    }
    return acceptOrContinue(item, deepFreeze(binding), input);
  }

  async function release(instructionId) {
    if (stopping) throw fail('Fixture is closed.', 409);
    const job = jobs.get(instructionId);
    if (!job) {
      if (inflight.has(instructionId)) await inflight.get(instructionId);
      if (!instructions.has(instructionId)) throw fail('Unknown instruction.', 404);
      return view(instructions.get(instructionId));
    }
    jobs.delete(instructionId);
    await acceptOrContinue(job.item, job.binding, job.input);
    return view(job.item);
  }

  // PROBE late-accept: the subject's ledger places its post-revocation acceptance before the revocation.
  function rewrite(list) {
    if (mode !== 'late-accept') return list;
    const late = list.findIndex(e => e.type === 'accepted' && e.instructionId === 'pre-cutoff');
    const revoked = list.findIndex(e => e.type === 'revoked');
    if (late < 0 || revoked < 0 || late < revoked) return list;
    const [moved] = list.splice(late, 1);
    list.splice(revoked, 0, { ...moved, atMs: list[revoked].atMs });
    return list.map((e, i) => ({ ...e, seq: i + 1 }));
  }
  async function snapshot({ horizonId, deadlineMs, close = false } = {}) {
    if (!boundedId(horizonId)) throw fail('A horizon identity is required.');
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > 5000 || typeof close !== 'boolean') throw fail('A bounded completion deadline and explicit closure state are required.');
    if (registeredBoundary && (registeredBoundary.id !== horizonId || registeredBoundary.deadlineMs !== deadlineMs)) throw fail('Cannot replace an established horizon or deadline.', 409);
    if (!registeredBoundary) registeredBoundary = deepFreeze({ id: horizonId, deadlineMs, startedAtMs: close ? 0 : now() });
    // Seal registration before yielding to the drain. Previously registered
    // deliveries/jobs remain accounted; later HTTP requests cannot join them.
    if (close) registrationClosed = true;
    // Bounded provider operations settle; deterministic holds and never-completing work do not block capture.
    await Promise.allSettled([...inflight.values()]);
    if (registeredBoundary.id !== horizonId || registeredBoundary.deadlineMs !== deadlineMs) throw fail('Cannot replace an established horizon or deadline.', 409);
    const pendingWork = new Set([...instructions.values()].filter(item => item.state === 'pending').map(item => item.binding.instructionId));
    for (const id of [...jobs.keys(), ...inflight.keys()]) pendingWork.add(id);
    // Delivery starts before parsing a request's instruction identity. A slow body
    // cannot disappear from a horizon just because it has not reached acceptance.
    for (const id of inbound.values()) pendingWork.add(id);
    const pending = pendingWork.size;
    if (close && !closedHorizon) {
      closedAtMs = now();
      closedHorizon = deepFreeze({ id: horizonId, deadlineMs, closed: pending === 0, sealed: pending === 0, watermark: sequence, pending });
    }
    const horizon = closedHorizon ?? { id: horizonId, deadlineMs, closed: false, sealed: false, watermark: sequence, pending };
    const lateEvents = closedHorizon ? sequence - closedHorizon.watermark : 0;
    const outsideInterval = events.some(item => item.atMs < registeredBoundary.startedAtMs || (closedAtMs !== null && item.atMs > closedAtMs));
    const complete = horizon.closed && horizon.sealed && pending === 0 && lateEvents === 0 && !outsideInterval;
    return deepFreeze({ schema: 'scopehaven-refund-app-evidence/1', runId, targetId, buildHash, sourceId,
      events: rewrite(structuredClone(events)), instructions: [...instructions.values()].map(view),
      coverage: { source: 'application', complete, ordered: true, fromSeq: 1, toSeq: sequence, lateEvents,
        problems: [...(!horizon.closed || pending > 0 ? ['application-work-pending'] : []), ...(lateEvents > 0 ? ['late-application-events'] : []),
          ...(outsideInterval ? ['application-event-outside-interval'] : [])] },
      timing: { clockId, startedAtMs: registeredBoundary.startedAtMs, closedAtMs },
      horizon: { ...horizon, pending: Math.max(horizon.pending, pending) } });
  }

  const server = createServer(async (req, res) => {
    let deliveryId;
    try {
      if (stopping || !localHostAllowed(req, server.address()) || req.headers.origin !== undefined || req.headers['sec-fetch-site'] !== undefined) return json(res, 403, { error: 'Local non-browser requests only.' });
      const actor = identities.get(bearer(req));
      if (!actor) return json(res, 401, { error: 'Actor authentication required.' });
      if (req.method === 'GET' && req.url === '/identity') return json(res, 200, { principalId: actor.principalId, tenantId: actor.tenantId });
      if (req.method === 'POST' && req.url === '/refund') {
        if (registrationClosed) return json(res, 409, { error: 'Workflow registration is closed.' });
        deliveryId = randomUUID();
        inbound.set(deliveryId, `delivery-${deliveryId}`);
        const input = await body(req, 8192);
        if (boundedId(input?.instructionId)) inbound.set(deliveryId, input.instructionId);
        const result = await invoke(actor, input);
        return json(res, result.status, result.body);
      }
      if (req.method === 'GET' && req.url.startsWith('/instructions/')) {
        const id = decodeURIComponent(req.url.slice('/instructions/'.length));
        if (!boundedId(id)) throw fail('Invalid instruction identity.');
        const item = instructions.get(id);
        if (!item) return json(res, 404, { error: 'Instruction not found.' });
        if (item.binding.principalId !== actor.principalId || item.binding.tenantId !== actor.tenantId) return json(res, 403, { error: 'Instruction access refused.' });
        return json(res, 200, view(item));
      }
      return json(res, 404, { error: 'Endpoint not found.' });
    } catch (error) {
      if (!res.headersSent && !res.destroyed) json(res, error.status ?? 500, { error: error.status ? error.message : 'Fixture request failed.' });
    } finally {
      if (deliveryId) inbound.delete(deliveryId);
    }
  });
  server.requestTimeout = 3000;
  server.headersTimeout = 3000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function close() {
    if (stopping) return;
    stopping = true;
    for (const req of outbound) req.destroy(fail('Fixture stopped.'));
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
    await Promise.allSettled([...inflight.values()]);
  }
  return Object.freeze({ origin, actors, buildHash, authorize, revoke, release, snapshot, close });
}
