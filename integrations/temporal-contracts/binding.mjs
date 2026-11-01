// Pure normalization and causal joins. This module never authenticates evidence.
import { createHash } from 'node:crypto';

const FIELDS = Object.freeze(['instructionId', 'authorityId', 'principalId', 'tenantId', 'operation', 'chargeId', 'amount', 'currency', 'destinationDigest']);
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const digest = x => createHash('sha256').update(x).digest('hex');
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}
export function freezeEvidence(value) {
  if (value !== null && typeof value === 'object') { for (const child of Object.values(value)) freezeEvidence(child); Object.freeze(value); }
  return value;
}
export function bindingOf(record) {
  const value = object(record?.binding) ? record.binding : record;
  if (!object(value)) return null;
  if (object(record?.binding) && ['instructionId', 'authorityId', 'principalId', 'tenantId'].some(k => record[k] !== undefined && record[k] !== value[k])) return null;
  if (value.destinationDigest !== undefined && value.destination !== undefined &&
    (typeof value.destination !== 'string' || digest(value.destination) !== value.destinationDigest)) return null;
  const destinationDigest = typeof value.destinationDigest === 'string' && HASH.test(value.destinationDigest)
    ? value.destinationDigest : typeof value.destination === 'string' && value.destination.length > 0 && value.destination.length <= 200 ? digest(value.destination) : null;
  const result = Object.fromEntries(FIELDS.map(field => [field, field === 'destinationDigest' ? destinationDigest : value[field] ?? null]));
  if (FIELDS.filter(k => k.endsWith('Id')).some(k => typeof result[k] !== 'string' || !ID.test(result[k])) || result.operation !== 'refund'
    || !Number.isSafeInteger(result.amount) || result.amount <= 0 || result.amount > 100_000_000 || !/^[a-z]{3}$/.test(result.currency ?? '') || !destinationDigest) return null;
  return Object.freeze(result);
}
export function sameBinding(a, b) {
  const left = bindingOf(a), right = bindingOf(b);
  return left !== null && right !== null && FIELDS.every(k => left[k] === right[k]);
}
function unique(rows, keyOf, problems, label) {
  const result = new Map();
  if (!Array.isArray(rows) || rows.length > 10000) { problems.add(`${label}-missing-or-oversized`); return result; }
  for (const row of rows) {
    if (!object(row)) { problems.add(`${label}-invalid-record`); continue; }
    const key = keyOf(row);
    if (key === null || key === undefined || key === '') { problems.add(`${label}-missing-identity`); continue; }
    if (result.has(key)) {
      if (canonical(result.get(key)) !== canonical(row)) problems.add(`${label}-conflicting-identity:${String(key).slice(0, 128)}`);
    } else result.set(key, row);
  }
  return result;
}
export function bindTemporalFacts({ application, payments, contract, operator }) {
  const problems = new Set();
  const expected = unique(contract?.authorities, row => row.instructionId, problems, 'authority');
  const sourceInstructions = unique(application?.instructions, row => row.instructionId ?? row.binding?.instructionId, problems, 'instruction');
  const appEvents = unique(application?.events, row => Number.isSafeInteger(row.seq) && row.seq > 0 ? row.seq : null, problems, 'application-event');
  const orderedEvents = [...appEvents.values()].sort((a, b) => a.seq - b.seq);
  if (orderedEvents.some((row, i) => row.seq !== i + 1)) problems.add('application-sequence-gap');
  const knownTypes = ['authorized', 'arrived', 'accepted', 'refused', 'revoked', 'attempt', 'terminal'];
  for (const event of orderedEvents) if (!knownTypes.includes(event.type)) problems.add('application-event-unknown-type');
  const expectedAuthorityIds = new Set();
  for (const [id, row] of expected) {
    if (!bindingOf(row)) problems.add(`authority-invalid-binding:${id}`);
    if (expectedAuthorityIds.has(row.authorityId)) problems.add('authority-duplicate-authority-id');
    expectedAuthorityIds.add(row.authorityId);
  }
  const instructions = [...sourceInstructions.entries()].map(([instructionId, row]) => {
    const binding = bindingOf(row), authority = expected.get(instructionId);
    if (!binding) problems.add(`instruction-invalid-binding:${instructionId}`);
    if (!authority) problems.add(`instruction-without-expected-authority:${instructionId}`);
    else if (!sameBinding(binding, authority)) problems.add(`instruction-expected-authority-binding-conflict:${instructionId}`);
    return { ...row, ...binding, instructionId, binding, authorityValid: Boolean(authority && sameBinding(binding, authority)) };
  });
  const instructionsById = new Map(instructions.map(row => [row.instructionId, row]));
  for (const id of expected.keys()) if (!instructionsById.has(id)) problems.add(`instruction-missing:${id}`);
  const events = orderedEvents.map(row => {
    const binding = bindingOf(row), authority = expected.get(row.instructionId);
    if ((['authorized', 'accepted', 'attempt'].includes(row.type) || (row.type === 'refused' && authority)) && !binding) problems.add(`application-event-binding-missing-or-conflicting:${row.seq}`);
    return { ...row, ...(row.binding ? { binding } : {}), ...(authority ? { bindingValid: sameBinding(binding, authority) } : {}) };
  });
  for (const event of orderedEvents) {
    if (event.instructionId && !expected.has(event.instructionId) && (['authorized', 'accepted', 'attempt'].includes(event.type)
      || (event.type === 'terminal' && event.state === 'success'))) problems.add(`application-event-without-expected-authority:${event.instructionId}`);
  }
  for (const check of contract?.requiredChecks ?? []) {
    if (check.kind !== 'refusal') continue;
    for (const instructionId of check.instructionIds ?? []) {
      if (!events.some(row => row.type === 'refused' && row.instructionId === instructionId && row.bindingValid === true)) problems.add(`required-refusal-binding-unestablished:${instructionId}`);
    }
  }
  const appAttempts = unique(orderedEvents.filter(row => row.type === 'attempt'), row => row.attemptId, problems, 'application-attempt');
  const providerRows = unique(payments?.lineage, row => Number.isSafeInteger(row.seq) && row.seq > 0 ? row.seq : null, problems, 'provider-attempt');
  const source = payments?.attempts?.source, instanceId = payments?.observer?.instanceId, epoch = payments?.window?.from?.epoch;
  const qualifiedEffect = id => typeof id === 'string' && ID.test(id) && source && instanceId && typeof epoch === 'string' && ID.test(epoch)
    ? `${source}:${instanceId}:${epoch}:${id}` : null;
  if (source !== 'http-egress' || typeof instanceId !== 'string' || !ID.test(instanceId) || typeof epoch !== 'string' || !ID.test(epoch)
    || payments?.window?.to?.epoch !== epoch) problems.add('provider-source-identity-invalid');
  const providerAttemptIds = new Set();
  const attempts = [...providerRows.values()].sort((a, b) => a.seq - b.seq).map(row => {
    const binding = bindingOf(row), applicationAttempt = appAttempts.get(row.attemptId), instruction = instructionsById.get(row.instructionId);
    const metadataValid = row.runId === contract?.runId && typeof row.attemptId === 'string' && ID.test(row.attemptId)
      && binding && row.currency === binding.currency && row.instructionId === binding.instructionId && row.authorityId === binding.authorityId
      && row.principalId === binding.principalId && row.tenantId === binding.tenantId && Array.isArray(row.problems) && row.problems.length === 0;
    if (!metadataValid) problems.add(`provider-attempt-missing-or-mismatched-metadata:${row.seq}`);
    if (!expected.has(row.instructionId)) problems.add(`provider-attempt-without-expected-authority:${row.seq}`);
    if (providerAttemptIds.has(row.attemptId)) problems.add(`provider-attempt-id-reused:${row.attemptId}`);
    providerAttemptIds.add(row.attemptId);
    if (!applicationAttempt) problems.add(`provider-attempt-without-application-dispatch:${row.seq}`);
    const lineageValid = Boolean(metadataValid && applicationAttempt && applicationAttempt.instructionId === row.instructionId && sameBinding(applicationAttempt, binding));
    if (applicationAttempt && !lineageValid) problems.add(`dispatch-provider-binding-conflict:${row.seq}`);
    return { attemptId: row.attemptId ?? `unbound:${row.seq}`, instructionId: row.instructionId, runId: row.runId, source, instanceId, epoch,
      seq: applicationAttempt?.seq ?? null, providerSeq: row.seq, applicationSeq: applicationAttempt?.seq ?? null, atMs: applicationAttempt?.atMs ?? null,
      binding, lineageValid, bindingValid: Boolean(instruction?.authorityValid && sameBinding(binding, instruction.binding)),
      providerStatus: row.providerStatus, replayed: row.replayed, created: row.created, effectId: qualifiedEffect(row.effectId), providerEffectId: row.effectId };
  });
  const attemptsBySeq = new Map(attempts.map(row => [row.providerSeq, row]));
  const attemptsById = new Map(attempts.map(row => [row.attemptId, row]));
  for (const [attemptId] of appAttempts) if (!attemptsById.has(attemptId)) problems.add(`application-dispatch-without-provider-observation:${attemptId}`);
  // Every protected send remains visible, including a refused operation whose
  // causal metadata is missing. The old generic send list is not silently lost.
  for (const row of payments?.attempts?.events ?? []) {
    if (row.operation === 'send' && row.resource !== 'read' && row.name === payments?.scope?.names?.[0] && !attemptsBySeq.has(row.seq)) problems.add(`unbound-provider-send:${row.seq}`);
  }
  const refunds = unique(payments?.refunds, row => qualifiedEffect(row.id), problems, 'refund-effect');
  const effects = [...refunds.entries()].map(([effectId, row]) => {
    const attempt = attemptsBySeq.get(row.seq);
    if (!attempt || !attempt.created || attempt.providerEffectId !== row.id || attempt.providerStatus !== 200) problems.add(`refund-effect-without-creating-attempt:${row.id}`);
    const payloadMatches = Boolean(attempt?.binding && row.charge === attempt.binding.chargeId && row.amount === attempt.binding.amount
      && row.currency === attempt.binding.currency && row.destinationDigest === attempt.binding.destinationDigest);
    if (!payloadMatches) problems.add(`refund-effect-binding-conflict:${row.id}`);
    return { effectId, providerEffectId: row.id, refundId: row.id, source, instanceId, epoch, seq: row.seq, attemptId: attempt?.attemptId ?? null,
      instructionId: attempt?.instructionId ?? null, binding: attempt?.binding ?? null, chargeId: row.charge, amount: row.amount, currency: row.currency,
      destinationDigest: row.destinationDigest, toOriginalMethod: row.toOriginalMethod,
      bound: Boolean(attempt?.lineageValid && payloadMatches), bindingValid: Boolean(attempt?.bindingValid && payloadMatches), state: 'success' };
  });
  const effectsById = new Map(effects.map(row => [row.effectId, row]));
  for (const attempt of attempts) {
    if (attempt.effectId && !effectsById.has(attempt.effectId)) problems.add(`attempt-effect-outside-window:${attempt.attemptId}`);
    if (attempt.created && !effects.some(row => row.seq === attempt.providerSeq)) problems.add(`creating-attempt-missing-effect:${attempt.attemptId}`);
  }
  const terminals = orderedEvents.filter(row => row.type === 'terminal').map(row => {
    if (!['success', 'failure', 'pending'].includes(row.state)) problems.add(`terminal-state-unknown:${row.instructionId}`);
    const effectId = row.effectId ? qualifiedEffect(row.effectId) : null;
    const effect = effectsById.get(effectId);
    const creatingAttempt = attemptsById.get(effect?.attemptId);
    const causallyAfterDispatch = Boolean(creatingAttempt && Number.isSafeInteger(creatingAttempt.applicationSeq) && row.seq > creatingAttempt.applicationSeq
      && Number.isFinite(row.atMs) && Number.isFinite(creatingAttempt.atMs) && row.atMs >= creatingAttempt.atMs);
    if (row.state === 'success' && effect && !causallyAfterDispatch) problems.add(`${Number.isFinite(row.atMs) && Number.isFinite(creatingAttempt?.atMs)
      ? 'terminal-success-before-creating-dispatch' : 'terminal-success-order-unestablished'}:${row.instructionId}`);
    return { ...row, effectId, providerEffectId: row.effectId ?? null,
      effectBound: Boolean(effect?.bound && effect?.bindingValid && effect.instructionId === row.instructionId && causallyAfterDispatch) };
  });
  const revocations = orderedEvents.filter(row => row.type === 'revoked').map(row => {
    if (typeof row.principalId !== 'string' || !ID.test(row.principalId)) problems.add('application-revocation-principal-missing');
    return { ...row, effectiveSeq: row.seq };
  });
  // A header is checked against the enclosing operator operation; it never
  // chooses the operation to which an effect is charged. Unscoped sends cannot
  // disappear into a later instruction with the same payment payload.
  let observed = null;
  if (operator?.operations?.length) {
    const issues = new Set(), windows = operator.operations;
    const validWindows = windows.every((w, i) => w.complete && Number.isSafeInteger(w.fromSeq) && Number.isSafeInteger(w.toSeq)
      && w.fromSeq <= w.toSeq && w.epoch === epoch && Number.isFinite(w.startMs) && Number.isFinite(w.endMs)
      && w.startMs >= 0 && w.endMs >= w.startMs && (!i || (w.index > windows[i-1].index && w.startMs >= windows[i-1].endMs && w.fromSeq >= windows[i-1].toSeq)));
    if (!validWindows) issues.add('operator-windows-incomplete');
    const windowFor = seq => {
      const matches = windows.filter(w => seq > w.fromSeq && seq <= w.toSeq);
      return matches.length === 1 ? matches[0] : null;
    };
    const observedAttempts = attempts.map(attempt => {
      const row = providerRows.get(attempt.providerSeq), window = windowFor(attempt.providerSeq);
      const authority = expected.get(window?.instructionId);
      const headerMatches = Boolean(authority && row.runId === contract.runId && sameBinding(row, authority));
      if (!window || !authority) issues.add(`provider-send-outside-operator-window:${attempt.providerSeq}`);
      else if (!headerMatches) issues.add(`provider-header-window-mismatch:${attempt.providerSeq}`);
      const input = window?.input ?? {};
      const requestMatches = Boolean(authority && window.principalId === authority.principalId &&
        Object.keys(input).filter(k => FIELDS.includes(k) || k === 'destination').every(k => input[k] === authority[k]));
      return { ...attempt, instructionId: window?.instructionId ?? null, claimedInstructionId: row.instructionId,
        windowIndex: window?.index ?? null, operatorStartMs: window?.startMs ?? null, operatorEndMs: window?.endMs ?? null,
        binding: authority ? bindingOf(authority) : null, claimedBinding: attempt.binding, headerMatches, requestMatches,
        bindingValid: headerMatches && requestMatches, lineageValid: Boolean(window && authority) };
    });
    const observedEffects = effects.map(effect => {
      const attempt = observedAttempts.find(a => a.providerSeq === effect.seq), authority = attempt?.binding;
      const payloadMatches = Boolean(authority && effect.chargeId === authority.chargeId && effect.amount === authority.amount &&
        effect.currency === authority.currency && effect.destinationDigest === authority.destinationDigest);
      return { ...effect, instructionId: attempt?.instructionId ?? null, binding: authority ?? null,
        windowIndex: attempt?.windowIndex ?? null, operatorEndMs: attempt?.operatorEndMs ?? null,
        bound: Boolean(authority), bindingValid: payloadMatches };
    });
    observed = { ...operator, attempts: observedAttempts, effects: observedEffects,
      coverage: validWindows && payments?.coverage === 'complete' && payments?.scope?.evidence === 'authoritative'
        && ![...issues].some(p => p.startsWith('provider-send-outside-operator-window')) ? 'complete' : 'incomplete', problems: [...issues] };
  }
  return freezeEvidence({ instructions, events, attempts, effects, revocations, terminals, operator: observed, timing: application?.timing ?? null,
    horizon: application?.horizon ?? null, problems: [...problems].sort() });
}
