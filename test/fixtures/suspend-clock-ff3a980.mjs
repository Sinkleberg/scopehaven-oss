// Frozen copy of scopehaven/src/suspend-clock.mjs at ff3a980 (main after the suspend-aware lead-in and stop, F4c, and in-doubt resolution
// IDR-2, before the suspend follow-ups, F4d; no imports to re-point). For test/suspend-f4d.test.mjs, main's side of the differential only.
// Not in any identity list.
// Suspend-aware custody time (F4, first slice: outputs/scopehaven-step1-2026-10-11/DP5-DEBRIEF.md section 7.3).
//
// A host that sleeps during a check stops the application, the in-process observers and the checker together, and on some hosts
// the checker's own clock keeps counting through it. Three clocks tell a suspend apart from a quiet application:
//   - awake: stops while the host is suspended;
//   - elapsed: keeps counting through a suspend, and is never stepped;
//   - wall: Date.now(), to say when, and to see a wall-clock step.
// Between two samples, elapsed advancing more than awake by more than the floor is a suspend; wall moving away from elapsed is a
// wall-clock step (NTP or a manual set), never a suspend. With no elapsed clock, wall advancing more than awake is a clock
// discontinuity (a suspend or a forward step, which the two clocks cannot tell apart), and wall falling behind awake is a step back.
// The floor is the larger of thresholdMs and driftRatio of the pair's length: an awake clock that under-reads a little (the CPU tick
// clock below, about 0.43% when idle) never adds up to a suspend over a long pair. An awake clock that has never moved is frozen or
// unread and decides nothing: no record, no extension. One that did move in an earlier pair but not at all in this one, where the
// timers count sleep and elapsed time passed the floor, fails closed: the whole pair is a suspend (it held no awake time).
//
// Node's own clock on macOS counts sleep. In Node 24.21.0 (libuv 1.52.1, src/unix/darwin.c uv__hrtime) every libuv clock reads
// mach_continuous_time: performance.now(), process.hrtime and the event loop's timers keep counting while the host sleeps, so a
// settle wait that spans a sleep ends at wake with less awake time than it asked for. That is elapsed time here, never awake time.
// On Linux, libuv reads CLOCK_MONOTONIC, which excludes suspend; no default is declared there yet (not run on Linux).
//
// What it changes (src/http-connector.mjs): a settle, horizon, barrier or final wait a suspend cut short in awake time is extended
// by the time it lost, within its bound; and a wait still short when the extension runs out of room did not hold its declared awake
// time, so its windows read partial (sealed under a timing plan as the awake time held, which the horizon rules read; without one as
// the record's shortMs, applySuspendShort). Under a timing plan the lead-in before an observed check is held in awake time too (H
// since the end of the last request), and a check whose lead-in is still short is not sent, nor any later one; without a plan a
// check whose settle or barrier was left short is the last one sent (SUSPEND_STOPPED), so a send the sleep displaced cannot land
// in a later check's window. Nothing here ever turns an undecided verdict into a pass or a fail: a shortfall only marks windows
// partial or stops the run, and a longer wait only gives the application its declared awake time. A window a suspend overlapped
// carries a record of it (src/effect-events.mjs validateWindow) that its gap basis names, and so does the text of a row decided on
// that coverage (src/http-effects.mjs effectAssertionRows).
import { cpus as systemCpus } from 'node:os';

export const SUSPEND_LIMITS = Object.freeze({ thresholdMs: 2000, driftRatio: 0.02, breaks: 1024, recordMs: 31 * 24 * 60 * 60 * 1000 });
// What a window's record says caused the break: a suspend the awake and elapsed clocks agree on, or a discontinuity that could
// also be a forward wall-clock step.
export const SUSPEND_CAUSES = Object.freeze(['host-sleep', 'clock-discontinuity']);
const HELD_KINDS = Object.freeze(['suspend', 'discontinuity']);

// The awake clock from the CPU tick counters (user, nice, sys, idle and irq, in ms; os.cpus()): every CPU's counters stop while
// the host is suspended, and the busiest CPU's counter is the current one, so each reading advances by the largest per-CPU step.
// Checked on darwin-arm64 (2026-10-15): per-CPU totals since boot were within 1% of CLOCK_UPTIME_RAW (mach_absolute_time) and
// about 236,700 s below mach_continuous_time on a host that had slept that long; over 250 ms samples the largest step stayed
// within 11 ms of performance.now(), and idle it under-reads by about 0.43% (SUSPEND_LIMITS.driftRatio covers that).
// The baseline is read when the clock is made. A reading is NaN (unusable) when the CPU list changes, is empty, has a bad counter or
// is all zeros; a reading in which no counter moved repeats the last total, so the detector reads that pair as a frozen clock.
export function cpuAwakeClock(cpus = systemCpus) {
  const totals = () => {
    try {
      const list = cpus();
      if (!Array.isArray(list) || !list.length) return null;
      const now = list.map(c => c.times.user + c.times.nice + c.times.sys + c.times.idle + c.times.irq);
      return now.every(Number.isFinite) && now.some(t => t > 0) ? now : null;
    } catch { return null; }
  };
  let prev = totals(), total = 0;
  return () => {
    const now = totals();
    if (now === null || prev === null || prev.length !== now.length) { prev = now; return NaN; }
    total += Math.max(0, ...now.map((t, i) => t - prev[i]));
    prev = now;
    return total;
  };
}

// The default clocks for this platform. darwin: elapsed is performance.now() (mach_continuous_time, see above) and awake the CPU
// tick clock; the run's timers count suspend there. Elsewhere no suspend can be seen yet: awake is null.
export function platformClocks({ platform = process.platform, cpus = systemCpus } = {}) {
  if (platform === 'darwin') return { wall: () => Date.now(), awake: cpuAwakeClock(cpus), elapsed: () => performance.now(), timersCountSuspend: true };
  return { wall: () => Date.now(), awake: null, elapsed: null, timersCountSuspend: false };
}

// A detector over injected clocks (each a function returning ms, or null when the platform has none). sample() reads them together
// and records each break it finds between this sample and the last usable one: { kind, ms, from, to }, where kind is 'suspend',
// 'discontinuity', 'wall-step' or 'unchecked', ms the suspended time (the signed step; the unchecked span), and from and to the two
// samples' readings ({ wall, awake, elapsed }, a clock without a reading null). A reading that throws or is not finite makes that
// sample unusable for that clock, and the next sample starts again from it. timersCountSuspend: the run's timers keep counting while
// the host is suspended (macOS), so a wait loses the awake time a suspend took from it (lostSince); there a pair longer than the
// threshold whose awake reading did not move is a suspend of the whole pair once the awake clock has moved in an earlier pair (it is
// alive: fail closed, PR343-REVIEW finding 2), and 'unchecked' (uncheckedSince) while it never has (none read, or frozen throughout):
// a suspend in it could not have been seen.
export function createSuspendDetector({ wall = () => Date.now(), awake = null, elapsed = null, thresholdMs = SUSPEND_LIMITS.thresholdMs, driftRatio = SUSPEND_LIMITS.driftRatio, timersCountSuspend = false } = {}) {
  if (typeof wall !== 'function' || ![awake, elapsed].every(c => c === null || typeof c === 'function') || !(thresholdMs > 0) || !(driftRatio >= 0 && driftRatio < 1)) throw new TypeError('suspend detector: invalid clocks');
  const read = clock => { if (clock === null) return null; try { const v = clock(); return Number.isFinite(v) ? v : null; } catch { return null; } };
  const floor = span => Math.max(thresholdMs, driftRatio * span);
  const kept = [];
  // alive: the awake clock has moved in some pair so far.
  let last = null, count = 0, alive = false;
  // Bounded: past the limit the oldest are dropped. The extension (lostSince) is computed from the same kept breaks as the record.
  const keep = entry => { count += 1; kept.push({ index: count, ...entry }); if (kept.length > SUSPEND_LIMITS.breaks) kept.shift(); };
  const copy = ({ index, ...e }) => ({ ...e, from: { ...e.from }, to: { ...e.to } });
  const detector = {
    timersCountSuspend: timersCountSuspend === true,
    sample() {
      const now = { wall: read(wall), awake: read(awake), elapsed: read(elapsed) }, prev = last;
      last = now;
      if (prev === null || now.wall === null || prev.wall === null) return [];
      const step = key => (prev[key] === null || now[key] === null ? null : now[key] - prev[key]);
      const dWall = step('wall'), dAwake = step('awake'), dElapsed = step('elapsed');
      // A monotonic clock that went back is not a reading: nothing is decided from this pair.
      if ((dAwake !== null && dAwake < 0) || (dElapsed !== null && dElapsed < 0)) return [];
      // An awake clock that did not move at all decides no suspend or discontinuity while it has never moved (frozen or unread). Once
      // it has (alive), a pair over which it read no movement while the timers counted elapsed time held no awake time: where the
      // timers count suspend that is a suspend of the whole pair (stilled; a sleep that began the instant a wait did), never unchecked.
      const moved = dAwake !== null && dAwake > 0;
      const stilled = detector.timersCountSuspend && alive && dAwake === 0 && dElapsed !== null;
      const found = [];
      if (dAwake !== null && dElapsed !== null) {
        if ((moved || stilled) && dElapsed - dAwake > floor(dElapsed)) found.push({ kind: 'suspend', ms: dElapsed - dAwake });
        if (Math.abs(dWall - dElapsed) > thresholdMs) found.push({ kind: 'wall-step', ms: dWall - dElapsed });
      } else if (dAwake !== null) {
        if (moved && dWall - dAwake > floor(dWall)) found.push({ kind: 'discontinuity', ms: dWall - dAwake });
        else if (dWall - dAwake < -thresholdMs) found.push({ kind: 'wall-step', ms: dWall - dAwake });
      } else if (dElapsed !== null && Math.abs(dWall - dElapsed) > thresholdMs) found.push({ kind: 'wall-step', ms: dWall - dElapsed });
      // Where the timers count suspend, a pair longer than the threshold with no moving awake reading and no live awake clock (none,
      // an unreadable one, or one that has never moved) could have hidden a suspend: it is unchecked, never a suspend and never lost time.
      const span = dElapsed ?? dWall;
      if (detector.timersCountSuspend && !moved && !stilled && span > thresholdMs) found.push({ kind: 'unchecked', ms: span });
      if (moved) alive = true;
      const entries = found.map(f => ({ ...f, from: { ...prev }, to: { ...now } }));
      entries.forEach(keep);
      return entries.map(e => ({ ...e, from: { ...e.from }, to: { ...e.to } }));
    },
    // Sample, then a position: the breaks recorded so far.
    mark() { detector.sample(); return Object.freeze({ count }); },
    // The breaks recorded after mark `from` up to mark `to` (copies; the oldest may have been dropped past the limit).
    between(from, to) { return kept.filter(e => e.index > from.count && e.index <= to.count).map(copy); },
    // Sample, then the awake time the run's timers lost since the mark: the suspended time of the suspends kept since it, the same
    // breaks a window's record is made from; 0 where the timers do not count suspend (a wait there already lasts in awake time). A
    // discontinuity is never counted: it may be a forward wall step, which takes nothing from a timer on elapsed time.
    lostSince(mark) { detector.sample(); return detector.timersCountSuspend ? kept.filter(e => e.index > mark.count && e.kind === 'suspend').reduce((n, e) => n + e.ms, 0) : 0; },
    // Sample, then the time since the mark over which no suspend could have been seen though the timers count it (unchecked pairs).
    uncheckedSince(mark) { detector.sample(); return kept.filter(e => e.index > mark.count && e.kind === 'unchecked').reduce((n, e) => n + e.ms, 0); },
    // Copies of every break still kept.
    breaks() { return kept.map(copy); },
  };
  return detector;
}

const isoOf = ms => { const d = new Date(Math.round(ms)); return Number.isFinite(d.getTime()) ? d.toISOString() : null; };
// The wall times a sealed record can state (canonical ISO, years 0000 to 9999). A record's bounds are clamped into them, so every
// record suspendRecord writes validates: none is dropped, nor its shortfall with it, and none fails the run (PR343-REVIEW nit 6).
const ISO_MS = Object.freeze([Date.parse('0000-01-01T00:00:00.000Z'), Date.parse('9999-12-31T23:59:59.999Z')]);
const sealable = ms => Math.min(ISO_MS[1], Math.max(ISO_MS[0], ms));
// The wall time a break ended, measured from its first sample on the elapsed clock (or the wall clock without one), never before it:
// a wall-clock step back at wake cannot put the end before the start.
const endOf = b => b.from.wall + Math.max(0, Number.isFinite(b.from.elapsed) && Number.isFinite(b.to?.elapsed) ? b.to.elapsed - b.from.elapsed : (b.to?.wall ?? b.from.wall) - b.from.wall);
// The record a window carries for the breaks that overlapped it ({ cause, count, ms, from, to }, plus shortMs below), or null when
// none held time. Wall-clock steps are left out: a step takes no awake time. (The provider feed and audit-file observers do read
// Date.now() for their window bounds, so a step can tighten their windows; naming steps in the record is a follow-up.) cause is
// 'host-sleep' only when every break was a suspend the awake and elapsed clocks agree on. from is the earliest first sample on the
// wall clock, and to the latest end measured from it (endOf), so a break that is recorded always yields a record with from <= to
// (both clamped into the sealable years). shortMs (without a declared timing plan): the awake time the window's wait was still owed
// when its extension ran out of room (src/http-connector.mjs extendAwake), at most ms; the window then reads partial
// (applySuspendShort). Under a declared timing plan the shortfall is sealed in the timing record instead (the awake time each wait
// held), and the horizon rules read it.
export function suspendRecord(breaks, { shortMs = 0 } = {}) {
  const held = (Array.isArray(breaks) ? breaks : []).filter(b => HELD_KINDS.includes(b?.kind) && b.ms > 0 && Number.isFinite(b.from?.wall));
  if (!held.length) return null;
  const from = isoOf(sealable(Math.min(...held.map(b => b.from.wall)))), to = isoOf(sealable(Math.max(...held.map(endOf))));
  const ms = Math.min(SUSPEND_LIMITS.recordMs, Math.max(1, Math.round(held.reduce((n, b) => n + b.ms, 0))));
  if (from === null || to === null) return null;
  const short = Number.isFinite(shortMs) && shortMs > 0 ? Math.min(ms, Math.ceil(shortMs)) : 0;
  return { cause: held.every(b => b.kind === 'suspend') ? 'host-sleep' : 'clock-discontinuity', count: Math.min(held.length, SUSPEND_LIMITS.breaks), ms, from, to, ...(short ? { shortMs: short } : {}) };
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const canonicalIso = s => typeof s === 'string' && ISO.test(s) && isoOf(Date.parse(s)) === s;
// A sealed record, exactly as suspendRecord writes it.
export function validSuspendRecord(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record) || ![Object.prototype, null].includes(Object.getPrototypeOf(record))) return false;
  const keys = Object.keys(record).sort().join(','), short = Object.hasOwn(record, 'shortMs');
  return keys === (short ? 'cause,count,from,ms,shortMs,to' : 'cause,count,from,ms,to')
    && SUSPEND_CAUSES.includes(record.cause) && Number.isSafeInteger(record.count) && record.count >= 1 && record.count <= SUSPEND_LIMITS.breaks
    && Number.isSafeInteger(record.ms) && record.ms >= 1 && record.ms <= SUSPEND_LIMITS.recordMs && canonicalIso(record.from) && canonicalIso(record.to) && record.from <= record.to
    && (!short || (Number.isSafeInteger(record.shortMs) && record.shortMs >= 1 && record.shortMs <= record.ms));
}

// A wait a host suspend left short of its declared awake time (record.shortMs), without a declared timing plan: like a horizon cut
// short (src/http-timing.mjs applyHorizon), every authoritative window that did not fail reads partial with this code appended (the
// earlier codes dropped from the end when the 200-character reason limit needs it; destination-scoped entries never survive it), so
// no absence can pass on the time the sleep took. Its events are kept: a recorded match still decides. A window it already holds is
// returned unchanged, so the validator reads a sealed window as its fixed point (src/http-effects.mjs bindSealedWindows).
export const SUSPEND_SHORT = 'host-suspend-wait-short';
// The not-sent reason of every applicable check after one whose settle or barrier a host suspend left short, without a declared timing
// plan (src/http-connector.mjs; the validator derives it from the sealed windows, src/contracts.mjs capturePreconditions): a send the
// sleep displaced past that check's end marks could otherwise land in a later check's window and decide it.
export const SUSPEND_STOPPED = 'host-suspend-run-stopped';
export const carriesSuspendShort = window => typeof window?.reason === 'string' && window.reason.split(',').includes(SUSPEND_SHORT);
export function applySuspendShort(window) {
  if (!(window?.suspend?.shortMs > 0) || window.scope?.evidence !== 'authoritative' || window.coverage === 'failed') return window;
  if (window.coverage === 'partial' && carriesSuspendShort(window) && !Object.hasOwn(window, 'scoped')) return window;
  const codes = (window.reason ? window.reason.split(',') : []).filter(c => c !== SUSPEND_SHORT);
  while (codes.length && [...codes, SUSPEND_SHORT].join(',').length > 200) codes.pop();
  const { scoped, ...rest } = window;
  return { ...rest, coverage: 'partial', reason: [...codes, SUSPEND_SHORT].join(',') };
}

// 'about 112 s between ... and ...' (or '3 times, about 112 s in all, between ... and ...').
const spanOf = record => {
  const seconds = Math.max(1, Math.round(record.ms / 1000));
  return `${record.count === 1 ? `about ${seconds} s` : `${record.count} times, about ${seconds} s in all,`} between ${record.from} and ${record.to}`;
};
// The words a gap basis adds for a window's record (', host suspended (sleep) about 112 s between ... and ..., and its wait held
// about 25 s less awake time than declared'), or '' without one.
export function suspendNote(record) {
  if (record === undefined || record === null) return '';
  const short = record.shortMs > 0 ? `, and its wait held about ${Math.max(1, Math.round(record.shortMs / 1000))} s less awake time than declared` : '';
  return `, ${record.cause === 'host-sleep' ? 'host suspended (sleep)' : 'host clock discontinuity (a sleep or a wall-clock step)'} ${spanOf(record)}${short}`;
}
// The sentence a row decided on complete coverage ends with when its check's windows carry a record. A window whose wait the
// suspend left short reads partial, so where every break was a suspend (host-sleep) a complete one held its declared awake time; but
// a sleep can still lose a send, on this host as well as off it (a request in flight when the host slept, or one an application
// timer, counting the sleep, gave up on at wake), so the coverage is named as resting on what the observers received
// (docs/KNOWN-LIMITS.md, Observers). A discontinuity (no elapsed reading: a sleep or a forward wall-clock step) is never counted as
// lost time, so nothing extended a wait for it and the note does not say the waits held (PR343-REVIEW nit 5). '' without a record.
export function suspendHeldNote(record) {
  if (record === undefined || record === null) return '';
  if (record.cause === 'host-sleep') return `The host was suspended (sleep) ${spanOf(record)} while this check's windows were open; its waits held their declared awake time, but a send the sleep cut off, on this host or off it, could have gone unseen.`;
  return `The host clock was discontinuous (a sleep or a wall-clock step) ${spanOf(record)} while this check's windows were open; a discontinuity is not counted as lost awake time, so its waits may have held less awake time than declared, and a send a sleep there cut off, on this host or off it, could have gone unseen.`;
}
// The sentence such a row ends with when its check's windows say no suspend could be checked (suspendUnchecked): the run's timers
// count host sleep but the awake clock gave no usable reading (none could be read, or it never moved in the run), so a sleep would
// not have been seen and a wait it cut short would read complete, as before this check existed.
export const SUSPEND_UNCHECKED_NOTE = 'Host sleep could not be checked while this check\'s windows were open (the run\'s timers count sleep, but the awake clock gave no usable reading: none could be read, or it never moved): a sleep there would not have been seen, and a wait it cut short would read complete.';
