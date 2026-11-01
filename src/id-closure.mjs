// Attribution through returned ids (readiness edge E3). Pure: no I/O.
//
// A forwarded destination that declares proofVersion 2 and ids (src/effect-outcome.mjs) has the declared ids of each
// /2-proven reply body recorded on its send as salted digests: upstream.minted, the ids the upstream created for that
// request (a value the request itself carried is an echo and is never recorded as minted), and upstream.references, ids
// of other objects the upstream names. Per egress-recorder instance, in recorder order (seq), over every window of the run
// (each check's own, the settlement gaps and the barriers):
//   seed    a committed send in check k's own window whose upstream outcome is applied and that seedable(e, k) accepts
//           (src/http-attribution.mjs: not background-possible, fitting a selector of one of k's own clauses or claims,
//           and fitting no earlier check's selector): its minted ids join closure(k)
//   tie     any other send whose minted or referenced ids hit exactly one closure, as the closures stand at its position,
//           belongs to that check, and its minted ids join that closure (references never do)
// Contested ids tie nothing anywhere: an id minted by two sends anywhere in the run, or echoed (found in a request at a minted
// pointer) by any send, so a later mint or echo also undoes earlier ties. Only minted ids join closures, and a send joins one
// closure at most, so an uncontested id is in one closure at most. A recorder with any window that is not complete (a send in
// flight, a dropped or failed record, the event cap) may have hidden a second mint: its sends tie nothing.
// The owner of a send: k for a seed of k; otherwise the one closure its uncontested ids hit at its position; "ambiguous"
// when they hit two or more; null when they hit none. One pass in recorder order is causal: a send can carry only ids
// returned before it. Each recorder keeps its own closures (digests are salted per recorder, and seq orders one recorder).
//
// An owner says which check's object a send concerns, not which request caused it. src/http-attribution.mjs uses it in one
// place only: a matched background-possible send owned by the check shows its effect.exists pass is the check's own. It
// never decides a fail, never excuses a send owned by another check, and never touches an absence clause: a check whose
// request makes the application act on another check's object (an IDOR or wrong-object defect) produces exactly such a send.
import { custodyRunWindows } from './effect-events.mjs';

export const AMBIGUOUS = 'ambiguous';
const minted = e => Array.isArray(e?.upstream?.minted) ? e.upstream.minted : [];
const referenced = e => Array.isArray(e?.upstream?.references) ? e.upstream.references : [];
const echoed = e => Array.isArray(e?.upstream?.echoed) ? e.upstream.echoed : [];

// rows: [{ windows }] in run order; gaps: [windows] (rows.length + 1); barriers: per row, its windows, or undefined.
// seedable(event, k): whether a send in row k's own window may seed closure(k). Returns owner(event): a row index, AMBIGUOUS or null.
export function closureOwners(rows, gaps, barriers, seedable) {
  custodyRunWindows(rows, gaps, barriers, 'closureOwners');
  const located = [
    ...gaps.flatMap(g => g.map(w => ({ w, row: null }))),
    ...rows.flatMap((r, j) => r.windows.map(w => ({ w, row: j }))),
    ...(barriers ?? []).flatMap(b => b.map(w => ({ w, row: null }))),
  ];
  // Per recorder instance, its sends that carry returned ids, once each, in recorder order.
  const byInstance = new Map(), incomplete = new Set();
  for (const { w, row } of located) {
    if (w?.source !== 'http-egress' || !Array.isArray(w.events)) continue;
    if (w.coverage !== 'complete') incomplete.add(w.instanceId);
    for (const e of w.events) {
      if (!minted(e).length && !referenced(e).length && !echoed(e).length) continue;
      if (!byInstance.has(w.instanceId)) byInstance.set(w.instanceId, new Map());
      const sends = byInstance.get(w.instanceId);
      // A send in two windows (never from the recorder) counts once, in the window that attributes it to no check if either does.
      const prior = sends.get(e.seq);
      if (!prior) sends.set(e.seq, { e, row });
      else if (prior.row !== row) prior.row = null;
    }
  }
  const owners = new WeakMap();
  for (const [instanceId, sends] of byInstance) {
    if (incomplete.has(instanceId)) continue;
    const ordered = [...sends.values()].sort((a, b) => a.e.seq - b.e.seq);
    // An id minted by two sends, or echoed by any, is no one object the upstream created.
    const mintCount = new Map();
    for (const { e } of ordered) for (const d of minted(e)) mintCount.set(d, (mintCount.get(d) ?? 0) + 1);
    const contested = new Set([...[...mintCount].filter(([, n]) => n > 1).map(([d]) => d), ...ordered.flatMap(({ e }) => echoed(e))]);
    const holder = new Map();
    const join = (k, digests) => { for (const d of digests) if (!contested.has(d)) holder.set(d, k); };
    for (const { e, row } of ordered) {
      if (row !== null && e.outcome === 'committed' && e.upstream.outcome === 'applied' && minted(e).length && seedable(e, row)) { owners.set(e, row); join(row, minted(e)); continue; }
      const hits = new Set([...minted(e), ...referenced(e)].filter(d => !contested.has(d) && holder.has(d)).map(d => holder.get(d)));
      if (hits.size === 1) { const [k] = hits; owners.set(e, k); join(k, minted(e)); }
      else owners.set(e, hits.size ? AMBIGUOUS : null);
    }
  }
  return e => owners.get(e) ?? null;
}
