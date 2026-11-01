// Optional model identity for an HTTP run, from the existing model tap. No model
// generation is requested here. Three routes, each recorded as custody:
//   owned  Scopehaven starts the tap in its own process for the assessment window
//          (SCOPEHAVEN_MODEL_TAP_UPSTREAM and SCOPEHAVEN_MODEL_TAP_PORT), marks it
//          at both ends and stops it. custody 'tap-memory'.
//   live   the caller passes a started tap object (modelTap). Its marks and its
//          in-memory failure state are read here. custody 'tap-memory'.
//   file   Scopehaven reads a tap log file another process wrote
//          (SCOPEHAVEN_MODEL_TAP_LOG). It needs a final close frame. Any process
//          running as the log's user can rewrite and re-chain it, so it is a
//          reading only: custody 'tap-file', which the strict policy reads
//          unverified (subject-writable-custody). No head anchor is accepted.
import { openSync, closeSync, fstatSync, constants } from 'node:fs';
import { isAbsolute } from 'node:path';
import { readTapLog, modelIdentity, IDENTITY_SCHEMA, STRENGTHS } from '../integrations/model-identity/identity.mjs';
import { CHAIN_START, chainHash, createModelTap, TapLog, upstreamKind } from '../integrations/model-identity/tap.mjs';

export const MODEL_IDENTITY_CUSTODY = Object.freeze(['tap-memory', 'tap-file']);
// The only custody the strict policy accepts: frames held in Scopehaven's own process.
export const STRICT_CUSTODY = 'tap-memory';
// Environment names read for the owned tap. None holds a secret; an empty value counts as unset.
export const OWNED_TAP_ENV = Object.freeze({ upstream: 'SCOPEHAVEN_MODEL_TAP_UPSTREAM', port: 'SCOPEHAVEN_MODEL_TAP_PORT', ollamaTags: 'SCOPEHAVEN_MODEL_TAP_OLLAMA_TAGS' });
export function ownedTapConfig(env = {}) {
  const read = name => typeof env?.[name] === 'string' && env[name] !== '' ? env[name] : undefined;
  const config = { upstream: read(OWNED_TAP_ENV.upstream), port: read(OWNED_TAP_ENV.port), ollamaTags: read(OWNED_TAP_ENV.ollamaTags) };
  return Object.values(config).every(value => value === undefined) ? undefined : config;
}
// The owned tap forwards only to a literal loopback origin, listens only on 127.0.0.1 at the
// declared port (the application's model base URL points there), and never reaches a vendor.
function ownedOptions(config) {
  const port = typeof config?.port === 'string' && /^[1-9][0-9]{0,4}$/.test(config.port) ? Number(config.port) : typeof config?.port === 'number' ? config.port : NaN;
  const tags = config?.ollamaTags === undefined ? undefined : config.ollamaTags === 'true' || config.ollamaTags === true ? true : config.ollamaTags === 'false' || config.ollamaTags === false ? false : null;
  if (upstreamKind(config?.upstream) !== 'loopback' || !Number.isInteger(port) || port < 1 || port > 65535 || tags === null) return null;
  return { upstream: config.upstream, port, ...(tags === undefined ? {} : { ollamaTags: tags }) };
}

const MAX_LOG_BYTES = 64 * 1024 * 1024;
function framesOf(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('tap-log-unavailable');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_LOG_BYTES) throw new Error('tap-log-unavailable');
    return { frames: readTapLog(fd), fileId: `${stat.dev}:${stat.ino}` };
  } finally { closeSync(fd); }
}
const lastSeq = frames => frames.filter(f => Number.isSafeInteger(f.seq)).at(-1)?.seq ?? 0;
// A capture failure names only its own reason: no window, model or call is claimed.
const unknown = (reason, custody) => ({ schema: IDENTITY_SCHEMA, state: 'partial', strength: 'none', models: [], key: null,
  calls: { total: 0, succeeded: 0, failed: 0, abandoned: 0 }, replaced: [], reasons: [reason], window: null,
  tapSession: null, upstream: null, upstreamKind: null, head: null, routing: 'declared-by-operator', custody });
const prefixIntact = (before, after) => after.length >= before.length && before.every((f, i) => JSON.stringify(f) === JSON.stringify(after[i]));
function liveFrames(tap) {
  if (!Array.isArray(tap?.log?.frames) || tap.log.writeError || tap.log.overflow) throw new Error('tap-live-unavailable');
  const frames = structuredClone(tap.log.frames);
  let head = CHAIN_START, seq = 0;
  for (const frame of frames) {
    const { h, ...body } = frame;
    if (body.seq !== ++seq || h !== chainHash(head, body)) throw new Error('tap-live-invalid-chain');
    head = h;
  }
  return frames;
}
async function startMark(tap) {
  if (typeof tap?.mark !== 'function' || tap.inflight !== 0) throw new Error('tap-live-unavailable');
  const mark = await tap.mark(), frames = liveFrames(tap);
  if (!Number.isSafeInteger(mark?.seq) || mark.seq < 1 || !frames.some(f => f.seq === mark.seq && f.kind === 'models')) throw new Error('tap-live-invalid-mark');
  return { frames, from: mark.seq };
}

// path: a tap log file; tap: a caller's started tap; owned: { upstream, port, ollamaTags? } for a
// tap Scopehaven starts here. At most one may be configured; none keeps legacy absence.
export async function beginModelIdentityCapture({ path, tap, owned } = {}) {
  if (path === '') path = undefined; // An empty SCOPEHAVEN_MODEL_TAP_LOG is unconfigured.
  const configured = [path, tap, owned].filter(source => source !== undefined).length;
  if (!configured) return null; // Preserve legacy absence.
  if (configured > 1) return { failed: 'tap-capture-ambiguous-sources', custody: null };
  if (owned !== undefined) {
    const options = ownedOptions(owned);
    if (!options) return { failed: 'tap-owned-config-invalid', custody: 'tap-memory' };
    let started = null;
    try {
      const candidate = createModelTap({ ...options, log: new TapLog() });
      await candidate.start(); started = candidate;
      return { tap: started, owned: true, custody: 'tap-memory', ...await startMark(started) };
    } catch {
      if (started) await started.stop().catch(() => {});
      return { failed: 'tap-owned-unavailable-at-start', custody: 'tap-memory' };
    }
  }
  try {
    if (tap !== undefined) return { tap, custody: 'tap-memory', ...await startMark(tap) };
    const { frames, fileId } = framesOf(path);
    return { path, frames, fileId, from: lastSeq(frames), custody: 'tap-file' };
  } catch { return { failed: tap === undefined ? 'tap-log-unavailable-at-start' : 'tap-live-unavailable-at-start', custody: tap === undefined ? 'tap-file' : 'tap-memory' }; }
}
// Stops an owned tap if the run ends early. Safe to call more than once.
export async function releaseModelIdentityCapture(capture) {
  if (capture?.owned) await capture.tap.stop().catch(() => {});
}
export async function finishModelIdentityCapture(capture) {
  if (!capture) return undefined;
  if (capture.failed) return unknown(capture.failed, capture.custody);
  const atEnd = capture.owned ? 'tap-owned-unavailable-at-end' : capture.tap ? 'tap-live-unavailable-at-end' : 'tap-log-unavailable-at-end';
  try {
    let frames, to;
    if (capture.tap) {
      const mark = await capture.tap.mark();
      frames = liveFrames(capture.tap); to = mark?.seq;
      const inflight = capture.tap.inflight;
      // The owned tap stops here, after its end mark: its listener never outlives the window.
      await releaseModelIdentityCapture(capture);
      if (inflight !== 0 || !Number.isSafeInteger(to) || to <= capture.from || !frames.some(f => f.seq === to && f.kind === 'models')) return unknown(atEnd, capture.custody);
    } else {
      const read = framesOf(capture.path); frames = read.frames; to = lastSeq(frames);
      if (read.fileId !== capture.fileId) return unknown('tap-log-replaced-or-truncated', capture.custody);
      // A disk prefix cannot reveal a writer's missing in-memory failure gap.
      // Only a closing frame proves this file writer reached its end boundary.
      if (frames.at(-1)?.kind !== 'close' || frames.at(-1)?.inflight !== 0) return unknown('tap-log-not-closed-at-end', capture.custody);
    }
    if (!prefixIntact(capture.frames, frames)) return unknown('tap-log-replaced-or-truncated', capture.custody);
    return { ...modelIdentity(frames, { from: capture.from, to }), custody: capture.custody };
  } catch { await releaseModelIdentityCapture(capture); return unknown(atEnd, capture.custody); }
}

// Opt-in CI policy only; comparison and attribution semantics stay in W6 (attribute.mjs).
// Returns the gate reasons (fixed codes, in order) and why, as { side, reason } fixed codes.
// A relation of 'different' or 'silent-change' is comparable: strict requires comparable
// identity, not identical models, and the attribution rules decide whether a repair is credited.
const COMPARABLE_RELATIONS = Object.freeze(['same', 'different', 'silent-change']);
const CODE = /^[a-z0-9][a-z0-9-]{0,79}$/;
const codes = (list, limit = 8) => (Array.isArray(list) ? list : []).filter(code => typeof code === 'string' && CODE.test(code)).slice(0, limit);
export function strictModelIdentity(comparison, baseline, candidate) {
  const ma = comparison?.modelAttribution;
  if (!ma) return { reasons: [], causes: [] }; // A non-model-served subject has no identity to require.
  const sides = [['baseline', baseline], ['candidate', candidate]];
  if (ma.state !== 'recorded') {
    const malformed = Array.isArray(ma.malformed) ? ma.malformed : [];
    const causes = sides.flatMap(([side, run]) => malformed.includes(side) ? [{ side, reason: 'identity-unreadable' }]
      : run?.modelIdentity === undefined || run?.modelIdentity === null ? [{ side, reason: 'identity-absent' }] : []);
    if (malformed.includes('attribution-failed')) causes.push({ side: 'pair', reason: 'attribution-failed' });
    // Like the gate without this policy, a malformed identity keeps not-recorded beside it.
    return { reasons: [...(malformed.length ? ['model-identity-malformed'] : []), 'model-identity-not-recorded'], causes };
  }
  const unreadable = sides.filter(([, run]) => run.modelIdentity?.schema !== IDENTITY_SCHEMA
    || !STRENGTHS.includes(run.modelIdentity?.strength)
    || !run.modelIdentity.models.every(m => STRENGTHS.includes(m.strength)));
  if (unreadable.length) return { reasons: ['model-identity-malformed'], causes: unreadable.map(([side]) => ({ side, reason: 'identity-schema-or-strength-unreadable' })) };
  const causes = [];
  for (const [side, run] of sides) {
    const custody = run.modelIdentity.custody;
    // The custody rule: a reading the subject's user can rewrite is never part of a pass.
    if (custody !== STRICT_CUSTODY) causes.push({ side, reason: custody === 'tap-file' ? 'subject-writable-custody' : 'custody-not-recorded' });
    if (run.modelIdentity.state !== 'observed') causes.push({ side, reason: `model-${CODE.test(run.modelIdentity.state) ? run.modelIdentity.state : 'unrecognized'}` }, ...codes(run.modelIdentity.reasons).map(reason => ({ side, reason })));
  }
  if (!COMPARABLE_RELATIONS.includes(ma.relation)) causes.push(...(codes(ma.modelReasons).length ? codes(ma.modelReasons) : ['relation-unverifiable']).map(reason => ({ side: 'pair', reason })));
  return causes.length ? { reasons: ['model-identity-unverified'], causes } : { reasons: [], causes: [] };
}
// The first strict reason, or null (the GitHub Action names one decision reason).
export function strictModelIdentityReason(comparison, baseline, candidate) {
  return strictModelIdentity(comparison, baseline, candidate).reasons[0] ?? null;
}
