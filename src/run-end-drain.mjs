// Coverage v2 Part D, the bounded run-end drain: the record each egress recorder's drain leaves in the settlement record, and
// the rules that read it. Pure: no I/O. Kept apart from src/http-settlement.mjs, whose findings read no time (the record's
// waitedMs is shape-checked here and never decides anything).
//
// Coverage v2 Part D, the run-end drain: it runs only when the target declares attribution or a forwarded egress destination
// (target: a profile, or a saved run's { attribution, observers } records). Each drain record is { instanceId, quiescent,
// waitedMs, markClear, closedAfterCollect }, one per declared egress recorder in declaration order; a drain follows (the follow
// rule, src/effect-events.mjs unfollowedLate) only when it ended quiescent, its final mark was clear and no record pending at
// a collect had its connection closed after it.
// Feed v2, Part B (lead decision at GO): every witnessed provider feed on an endpoint also drains, whatever the egress gate: its
// signed head makes "nothing the provider accepted is unread" exact. Its record has the same shape (closedAfterCollect there reads
// a fault or a seq gap after its first late collect). drainersOf lists the drainers in declaration order: the egress recorders
// when drainsDeclared holds, and the drainable feeds.
export const DRAIN_LIMIT_MS = 600000;
const forwards = o => (Array.isArray(o?.destinations) && o.destinations.some(d => d?.forward)) || (o?.forward !== null && typeof o?.forward === 'object' && Object.keys(o.forward).length > 0);
export const drainsDeclared = target => (target?.attribution !== undefined && target?.attribution !== null) || (Array.isArray(target?.observers) && target.observers.some(o => o?.type === 'egress-recorder' && forwards(o)));
// A provider feed that drains: a profile entry with a witness on an endpoint, or a saved run's record that says witnessed and route endpoint.
export const drainsFeed = o => o?.type === 'provider-feed' && (Object.hasOwn(o, 'witnessed') ? o.witnessed === true && o.feed?.route === 'endpoint'
  : o.witness !== undefined && o.feed?.endpoint !== undefined && o.feed.endpoint !== null);
export const drainersOf = target => (Array.isArray(target?.observers) ? target.observers : []).filter(o => (o?.type === 'egress-recorder' && drainsDeclared(target)) || drainsFeed(o));
// drainers: the observers that drained (drainersOf), or any declared observer list, of which the egress recorders and drainable feeds count.
export function validDrains(drains, drainers) {
  const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const list = (Array.isArray(drainers) ? drainers : []).filter(o => o?.type === 'egress-recorder' || drainsFeed(o));
  return Array.isArray(drains) && drains.length === list.length && drains.length > 0 && drains.every((d, k) => plain(d) && Object.keys(d).sort().join(',') === 'closedAfterCollect,instanceId,markClear,quiescent,waitedMs'
    && d.instanceId === `${list[k].type}-${list[k].id}` && [d.quiescent, d.markClear, d.closedAfterCollect].every(v => typeof v === 'boolean') && Number.isSafeInteger(d.waitedMs) && d.waitedMs >= 0 && d.waitedMs <= DRAIN_LIMIT_MS);
}
// The drains' shared cap: the largest recorder's own cap, never past msLeft (the run deadline less the end-of-run identity
// probes still to send). 0 or less means no drain.
export const drainCapOf = (ownCaps, msLeft) => Math.max(0, Math.min(Math.max(0, ...ownCaps), Number.isFinite(msLeft) ? Math.floor(msLeft) : 0));
export const followedDrains = drains => new Set((Array.isArray(drains) ? drains : []).filter(d => d?.quiescent === true && d.markClear === true && d.closedAfterCollect === false).map(d => d.instanceId));
