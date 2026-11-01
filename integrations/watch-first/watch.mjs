// The watch run: the target once, with its observers on and no declarations.
// A watch file (scopehaven-watch/1) is a profile target without checks: the application, its actors and the observers
// the operator can give, plus the turns to send (an actor, a method, a path and an optional JSON body). Hand-written
// checks may ride along ("checks": { "first": [...], "last": [...] }, with their "requiredControlIds"); they are not sent
// in the watch and go into the draft unchanged, around the drafted lines (identity controls belong there).
// runWatch starts the observers, and for each turn marks every observer, sends the turn through the connector's own
// loopback transport (observeHttp: 127.0.0.1 only, no redirects or proxies), waits the largest declared settle, sends
// each observer's witness in the connector's order (marked for it with { headSplit: true }, then sent, then the end
// mark), marks the rest and collects one window per observer (collectWindow, the connector's collector, with each
// observer's declared settle applied). Windows are collected whole, not destination-scoped as a check's are: the draft
// reads a window's coverage as a whole. As in a run, an observer whose start or mark fails reads a failed window and the
// watch goes on; an authorization refusal (the window ended) stops it. It records what happened and judges nothing:
// the watch record (scopehaven-watch-record/1) holds each turn's status and the sealed windows, events by identifier
// and digest only, as a run keeps them. No model is called anywhere here.
import { validateTargetFile } from '../../src/contracts.mjs';
import { observeHttp, HTTP_LIMITS } from '../../src/http-connector.mjs';
import { collectWindow } from '../../src/effect-events.mjs';
import { applySettle, settleDeclared } from '../../src/http-effects.mjs';
import { canonical, sha256 } from '../policy-import/matrix.mjs';

export const WATCH_SCHEMA = 'scopehaven-watch/1';
export const WATCH_RECORD_SCHEMA = 'scopehaven-watch-record/1';
export const WATCH_LIMITS = Object.freeze({ turns: 64, checks: 64 });
const TURN_KEYS = ['id', 'actorId', 'method', 'path', 'body'];
const TURN_ID = /^[A-Za-z0-9_-]{1,40}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The watch file checked: its target is validated by the product's own validator (as the drafted profile will be), with
 * each turn standing in as a placeholder check; the placeholders are dropped again. Returns the watch, unchanged. */
export function validateWatch(watch) {
  if (!plain(watch) || watch.schema !== WATCH_SCHEMA) throw new Error(`A watch file needs schema "${WATCH_SCHEMA}".`);
  const extra = Object.keys(watch).find(k => !['schema', 'target', 'turns', 'checks', 'requiredControlIds'].includes(k));
  if (extra) throw new Error(`A watch file has no field "${extra}".`);
  if (!plain(watch.target) || Object.hasOwn(watch.target, 'checks') || Object.hasOwn(watch.target, 'requiredControlIds')) throw new Error('A watch file\'s "target" is a profile target without "checks" or "requiredControlIds" (those go beside it).');
  if (Object.hasOwn(watch.target, 'targetContext') && watch.target.targetContext !== 'local-app') throw new Error('A watch run is for a local application on loopback only.');
  if (!Array.isArray(watch.turns) || watch.turns.length < 1 || watch.turns.length > WATCH_LIMITS.turns) throw new Error(`A watch file needs 1 to ${WATCH_LIMITS.turns} turns.`);
  const ids = new Set();
  for (const [i, turn] of watch.turns.entries()) {
    const where = `turn ${i + 1}`;
    if (!plain(turn) || Object.keys(turn).some(k => !TURN_KEYS.includes(k))) throw new Error(`${where}: a turn is { id, actorId, method, path, body? }.`);
    if (typeof turn.id !== 'string' || !TURN_ID.test(turn.id) || ids.has(turn.id)) throw new Error(`${where}: needs a unique id of 1-40 letters, digits, "_" or "-".`);
    ids.add(turn.id);
  }
  const first = watch.checks?.first ?? [], last = watch.checks?.last ?? [];
  if (watch.checks !== undefined && (!plain(watch.checks) || Object.keys(watch.checks).some(k => !['first', 'last'].includes(k)) || !Array.isArray(first) || !Array.isArray(last))) throw new Error('"checks" is { "first": [...], "last": [...] } of hand-written checks.');
  if (first.length + last.length > WATCH_LIMITS.checks) throw new Error(`At most ${WATCH_LIMITS.checks} hand-written checks.`);
  if (watch.requiredControlIds !== undefined && !Array.isArray(watch.requiredControlIds)) throw new Error('"requiredControlIds" is a list of hand-written control ids.');
  watchProfileTarget(watch);
  return watch;
}

// A turn as the validator reads a check, for validation and credentials only: never sent as a check, never in the record.
const placeholder = turn => ({ id: turn.id, title: `Watch turn ${turn.id}`, category: 'Watch', severity: 'control', actorId: turn.actorId, method: turn.method, path: turn.path,
  ...(Object.hasOwn(turn, 'body') ? { body: turn.body } : {}), evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
/** The watch's target as the validator reads a profile target (for authorization and credentials), with the turns as placeholder checks. */
export const watchProfileTarget = watch => validateTargetFile({ schemaVersion: 1, targets: [{ ...watch.target, requiredControlIds: watch.requiredControlIds?.length ? watch.requiredControlIds : [watch.turns[0].id],
  checks: [...(watch.checks?.first ?? []), ...watch.turns.map(placeholder), ...(watch.checks?.last ?? [])] }] })[0];

// watchId and recordId are plain checksums: they catch an edit made without recomputing them, not a deliberate re-seal.
export const watchId = watch => sha256(canonical(watch));
export function verifyRecordId(record) {
  const { recordId, ...body } = record ?? {};
  return record?.schema === WATCH_RECORD_SCHEMA && typeof recordId === 'string' && recordId === sha256(canonical(body));
}

/** Runs the watch. env supplies the actors' and observers' credentials (SCOPEHAVEN_TARGET_ variables only, as a run reads
 * them); factory builds the observers (integrations/observers/factory.mjs buildObservers by default); beforeRequest, when
 * given, is called before every request (an authorization window's check), and a throw stops the watch. */
export async function runWatch(watch, { env = process.env, transport = observeHttp, factory, beforeRequest, now = () => new Date(), sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  validateWatch(watch);
  const profile = watchProfileTarget(watch);
  const credentials = Object.fromEntries(Object.entries(profile.actors).map(([alias, actor]) => [alias, actor.credentialEnv ? env[actor.credentialEnv] : undefined]));
  for (const [alias, actor] of Object.entries(profile.actors)) if (actor.credentialEnv && typeof credentials[alias] !== 'string') throw new Error(`Actor ${alias}'s credential (${actor.credentialEnv}) is not set.`);
  const send = (actorId, request) => {
    beforeRequest?.();
    const actor = profile.actors[actorId];
    return transport(profile.origin, request, { credential: credentials[actorId], credentialCookie: credentials[actorId] === undefined ? undefined : actor.credentialCookie, credentialHeader: credentials[actorId] === undefined ? undefined : actor.credentialHeader, timeoutMs: HTTP_LIMITS.requestTimeoutMs, maxResponseBytes: HTTP_LIMITS.responseBytes });
  };
  const configs = profile.observers ?? [];
  const build = factory ?? (await import('../observers/factory.mjs')).buildObservers;
  const observers = configs.length ? build(configs, { env }) : [];
  // As the connector wraps observers: a failed call reads no mark (a failed window), and only an authorization refusal stops the watch.
  const quiet = async (fn, fallback) => { try { return await fn(); } catch (error) { if (error?.name === 'AuthorizationError') throw error; return fallback; } };
  const settleMs = Math.max(0, ...configs.map(c => settleDeclared(c.settleMs) ? c.settleMs : 0));
  const startedAt = now().toISOString(), turns = [];
  let started = [];
  try {
    // Inside the try: an observer start the window refuses still stops every observer that did start.
    started = await Promise.all(observers.map(o => quiet(async () => { await o.start(); return true; }, false)));
    for (const turn of watch.turns) {
      const from = await Promise.all(observers.map((o, i) => started[i] ? quiet(() => o.mark(), null) : null));
      let observation;
      try { observation = await send(turn.actorId, { method: turn.method, path: turn.path, ...(Object.hasOwn(turn, 'body') ? { body: turn.body } : {}) }); }
      catch (error) { if (error?.name === 'AuthorizationError') throw error; observation = { status: null, complete: false, error: 'network' }; }
      if (settleMs) await sleep(settleMs);
      const to = await Promise.all(observers.map((o, i) => started[i] && !o.witnessRequest ? quiet(() => o.mark(), null) : null));
      const windows = new Array(observers.length);
      for (const [i, o] of observers.entries()) {
        if (!started[i]) { windows[i] = { source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: 'failed', reason: 'observer-not-started', events: [] }; continue; }
        if (o.witnessRequest) {
          // The connector's witness order: the witness after the turn's effects, so its own effects fall outside the window.
          if (from[i]) await quiet(() => o.markWitnessRequest?.(from[i], { headSplit: true }), null);
          if (typeof from[i]?.witnessNonce === 'string') {
            const w = o.witnessRequest;
            try { await send(w.actorId, { method: 'GET', path: `${w.path}${w.path.includes('?') ? '&' : '?'}scopehaven_witness=${encodeURIComponent(from[i].witnessNonce)}` }); } catch (error) { if (error?.name === 'AuthorizationError') throw error; }
          }
          to[i] = await quiet(() => o.mark(), null);
        }
        if (!from[i] || !to[i]) { windows[i] = { source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: 'failed', reason: 'observer-not-marked', events: [] }; continue; }
        windows[i] = applySettle(await collectWindow(o, from[i], to[i]), configs[i].settleMs);
      }
      turns.push({ id: turn.id, actorId: turn.actorId, method: turn.method, path: turn.path, ...(Object.hasOwn(turn, 'body') ? { body: turn.body } : {}),
        response: { status: observation.status ?? null, complete: observation.complete === true, transport: observation.error || (observation.complete === true ? 'complete' : 'incomplete') },
        windows: windows.map((w, i) => ({ observer: configs[i].id, type: configs[i].type, ...w })) });
    }
  } finally { await Promise.allSettled(observers.map(o => o.stop())); }
  const body = { schema: WATCH_RECORD_SCHEMA, watchId: watchId(watch), targetId: watch.target.id, applicationId: watch.target.applicationId, buildLabel: watch.target.buildLabel,
    startedAt, endedAt: now().toISOString(), settleMs, turns,
    scope: 'One watch run of a local application: what its declared observers recorded around each turn. No declaration, verdict or model; events are identifiers and digests.' };
  return { ...body, recordId: sha256(canonical(body)) };
}
