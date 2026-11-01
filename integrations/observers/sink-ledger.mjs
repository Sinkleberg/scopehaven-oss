// The window ledger shared by the loopback sinks (egress-recorder.mjs, smtp-sink.mjs).
// A sink records every unit it receives (an HTTP request, a mail transaction) in
// arrival order, and every problem it saw (a malformed request, a dropped
// connection) as a record of its own. A window is the records that arrived after
// the start mark, extended past the end mark until this window's witness has
// arrived and nothing has arrived for quietMs. The ledger decides what every sink
// decides the same way:
//   - failed: the sink was not listening at a mark, went down at any point since
//     the start mark (even after the end mark), or the window's records were evicted
//   - partial: a problem record in the window; a unit still in flight at collect;
//     this window's witness missing, duplicated or from another window; a unit that
//     arrived after the witness request was sent (never attributed to the check);
//     a late collect that missed arrivals; a sink still receiving after the cap
// It returns the units it can attribute; the sink turns them into events.
// Gap windows (run settlement, src/http-settlement.mjs): a window whose start is a
// check window's end mark begins where that window stopped attributing records (before
// its witness request, or at its quiet-period end), so a record that arrived between one
// window's collect and the next start mark falls in the gap, never in no window. A gap
// is an exact range up to its end mark: no witness, no waiting, and witness units skipped.
// Codes are "<prefix>-<what>" (unit: "request", "message").
import { randomUUID } from 'node:crypto';

// Every time the ledger compares (arrival, mark, quiet period, late collect, listener down) is monotonic: a step of the wall
// clock can neither fake a quiet period nor stall a wait. No wall time is stored; events carry their own observedAt.
const now = () => performance.now();
export const SINK_LEDGER_LIMITS = Object.freeze({ retained: 20000, pollMs: 50, lateCollectMs: 250 });

export function createSinkLedger({ prefix, unit, retained = SINK_LEDGER_LIMITS.retained }) {
  let seq = 0, evictedThrough = 0, lastArrivalAt = 0, epoch = null, listening = false, downAt = null;
  const records = [], witnessRequestAt = new Map();
  // End-mark nonce -> the last record its window attributed: where the next window starts.
  const attributedThrough = new Map();
  const code = what => `${prefix}-${what}`;
  return {
    // A unit ({ kind: 'item', done, witnessNonces, ... }) or a problem ({ kind: <problem> }).
    record(fields) {
      const r = { seq: ++seq, at: now(), done: true, ...fields };
      records.push(r); lastArrivalAt = r.at;
      if (records.length > retained) evictedThrough = records.shift().seq;
      return r;
    },
    started() { listening = true; downAt = null; epoch = randomUUID(); },
    down() { downAt ??= now(); },
    stopped() { listening = false; },
    position() { return { ok: listening && downAt === null, seq, at: now(), epoch, witnessNonce: randomUUID() }; },
    // The last recorded seq (for the egress recorder's close log).
    lastSeq() { return seq; },
    // Coverage v2 Part D (the egress recorder's run-end drain and final mark): the records not yet done, forwards still
    // settling included, and the time of the last arrival.
    // Once any record was evicted, a pending one may be among them: never zero again.
    notDone() { return evictedThrough > 0 ? Infinity : records.reduce((n, r) => n + (r.done ? 0 : 1), 0); },
    lastArrival() { return lastArrivalAt; },
    // Listening, and never down since it started (a mark's ok).
    up() { return listening && downAt === null; },
    // Called by the connector immediately before it sends this window's witness request.
    markWitnessRequest(from) { if (from?.ok && typeof from.witnessNonce === 'string') witnessRequestAt.set(from.witnessNonce, seq); },
    // scopedUnits (coverage v2, check windows only): the units a check window skips, after the witness request (deferred, done)
    // and still in flight (pending), are returned for the caller to classify, and their two unit codes are left to it. The gap
    // branch ignores the option. Without it the window is exactly as before.
    async window(from, to, { witness, witnessWaitMs, quietMs, gap = false, scopedUnits = false }) {
      if (!from?.ok || !to?.ok) return { failed: code('not-listening') };
      if (from.epoch !== epoch || to.epoch !== epoch || downAt !== null) return { failed: code('listener-down') };
      // Only a gap window starts where the previous window stopped attributing; every other window starts at its mark.
      const start = gap ? attributedThrough.get(from.witnessNonce) ?? from.seq : from.seq;
      if (start < evictedThrough) return { failed: code('records-evicted') };
      const problems = new Set();
      const inWindow = last => records.filter(r => r.seq > start && r.seq <= last);
      if (gap) {
        const items = [];
        for (const r of inWindow(to.seq)) {
          if (r.kind !== 'item') { problems.add(`${prefix}-${r.kind}-${unit}`); continue; }
          if (!r.done) { problems.add(code(`${unit}-in-flight`)); continue; }
          // The test's own witness units are never effects.
          if (r.witnessNonces.length) continue;
          items.push(r);
        }
        return { items, problems };
      }
      const witnessArrived = last => inWindow(last).some(r => r.done && r.witnessNonces?.includes(from.witnessNonce));
      let end = to.seq;
      const late = now() - to.at > SINK_LEDGER_LIMITS.lateCollectMs;
      if (late) { if (seq > to.seq) problems.add(code('collect-late')); }
      else if (witness) {
        // Wait for the witness, then until nothing has arrived for quietMs.
        const capMs = witnessWaitMs + 10 * quietMs, began = now();
        while (true) {
          end = seq;
          const found = witnessArrived(end), waited = now() - began;
          if (found ? now() - Math.max(lastArrivalAt, began) >= quietMs : waited >= witnessWaitMs) break;
          if (waited >= capMs) { problems.add(code('still-arriving')); break; }
          await new Promise(resolve => setTimeout(resolve, SINK_LEDGER_LIMITS.pollMs));
        }
        if (downAt !== null) return { failed: code('listener-down') };
        if (start < evictedThrough) return { failed: code('records-evicted') };
      }
      const requestAt = witnessRequestAt.get(from.witnessNonce) ?? Infinity; witnessRequestAt.delete(from.witnessNonce);
      attributedThrough.set(to.witnessNonce, Math.min(end, requestAt));
      const items = [], deferred = [], pending = [];
      let witnessSeen = false;
      for (const r of inWindow(end)) {
        if (r.kind !== 'item') { problems.add(`${prefix}-${r.kind}-${unit}`); continue; }
        if (!r.done) { if (scopedUnits) pending.push(r); else problems.add(code(`${unit}-in-flight`)); continue; }
        if (r.witnessNonces.length) {
          // The witness is the test's own unit, never an effect.
          if (r.witnessNonces.length === 1 && r.witnessNonces[0] === from.witnessNonce) { if (witnessSeen) problems.add(code('duplicate-witness')); witnessSeen = true; }
          else problems.add(code('foreign-witness'));
          continue;
        }
        // After the witness request was sent (or the witness itself), a unit cannot be attributed to the check.
        if (witnessSeen || r.seq > requestAt) { if (scopedUnits) deferred.push(r); else problems.add(code(`${unit}-after-witness-request`)); continue; }
        items.push(r);
      }
      if (witness && !witnessSeen) problems.add(code('witness-not-received'));
      return scopedUnits ? { items, problems, deferred, pending } : { items, problems };
    },
  };
}
