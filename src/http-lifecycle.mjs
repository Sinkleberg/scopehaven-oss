// Lifecycle phase for HTTP checks: an account change in the middle of a run. Pure: no I/O.
//
//   lifecycle: [{ changeCheckId, actorId, after: "refused" }]
//
// The check changeCheckId, an allowed-use control another actor sends (an administrator
// suspends, removes or demotes the user), changes actorId's standing. It may instead be sent by
// actorId itself (a self-change: the user signs out, revokes their own key or deletes their own
// account): see "Self-change" below. "refused" is the
// declared policy after it: the application refuses that actor's pre-change credential.
// It is a per-application policy, not a universal rule: an application whose sessions or
// tokens stay valid until they expire does not meet it, and is not tested by this field.
//
// The changed actor's checks split at the change:
//   - pre-change checks run as usual; the actor's identity proof (its brackets and the
//     anonymous, invalid and cross-actor probes, including every probe that carries its
//     credential) is completed strictly before the change check is sent
//   - the actor's surface control (a required GET on a protected route) shows, in the same brackets, that the
//     credential worked on the protected routes before the change: the same-actor acceptance a refusal needs
//   - post-change checks re-send the actor's unchanged pre-change credential. Each must
//     expect the policy's refusal (401, 403 or the actor's declared sign-in redirect) and
//     pair it with at least one effect.none clause, because a refusal status alone does not
//     show that nothing happened behind it. A credential that still works fails the row
//     on the harness's own observation of the status.
// When the change check did not pass at the time it was sent, the change is not confirmed
// and no post-change check is sent: each reads inconclusive, never pass or fail. When it passed
// but the run's attribution then withheld its pass, the change is not attributed: it reads
// unconfirmed and the post-change checks already sent never pass (change-not-attributed).
// The change check is sent by a credentialed actor with an identity control. When that actor's
// login was not proven for the change check (actor-identity/5), the change is not attributed:
// the post-change checks, already sent, read inconclusive (changer-login-unproven), never pass.
//
// Self-change (the change check's actor is actorId): the change check is a required allowed-use
// control of the changed actor that is not a GET (required GET controls are surface controls, re-sent
// at every probe point, so a sign-out GET would end the session mid-run). It is outside the actor's
// brackets, as its post-change checks are: the actor's last probe point comes before it, since the
// point after it is exactly what the policy says must now be refused. Its login rests on the actor's
// whole pre-change proof (every probe point, the anonymous, invalid and cross probes), so the change is
// attributed only when that proof holds. A self-change check serves no other entry. Every other rule
// above applies unchanged. A sign-out route that answers success without accepting the credential still
// confirms the change; a pre-change credential that then still works is the defect the user would see.
export const LIFECYCLE_POLICIES = Object.freeze(['refused']);
export const LIFECYCLE_LIMITS = Object.freeze({ entries: 10 });
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bad = message => { throw new Error(message); };
const applies = check => check.applicability?.applies !== false;

// Refusal statuses under the "refused" policy for one actor.
export const lifecycleRefusalStatuses = actor => [401, 403, ...(actor?.signInRedirectStatus ? [actor.signInRedirectStatus] : [])];
// The applicable checks of entry.actorId after its change check, in profile order.
export function postChangeChecks(checks, entry) {
  const at = checks.findIndex(c => c.id === entry.changeCheckId);
  return at < 0 ? [] : checks.slice(at + 1).filter(c => c.actorId === entry.actorId && applies(c));
}
// The change check ids of every self-change entry (the change check is sent by the changed actor itself).
export function selfChangeIds(target) {
  const byId = new Map((target.checks ?? []).map(c => [c.id, c]));
  return new Set((target.lifecycle ?? []).filter(e => byId.get(e.changeCheckId)?.actorId === e.actorId).map(e => e.changeCheckId));
}
// checkId -> entry for every post-change check of the profile.
export function postChangeIndex(target) {
  const index = new Map();
  for (const entry of target.lifecycle ?? []) for (const check of postChangeChecks(target.checks, entry)) index.set(check.id, entry);
  return index;
}

// Static rules, applied once checks, required controls and the identity plan are known.
// identityControlsOf(actorId) -> the actor's identity control ids. Throws with a message.
// surfaceControlsOf(actorId) -> the actor's surface controls (actor-identity/4): required GET controls on protected routes.
export function validateLifecycle(target, identityControlsOf, entryWithin, surfaceControlsOf = () => []) {
  const list = target.lifecycle;
  if (!Array.isArray(list) || list.length < 1 || list.length > LIFECYCLE_LIMITS.entries) bad(`"lifecycle" lists 1 to ${LIFECYCLE_LIMITS.entries} { changeCheckId, actorId, after }`);
  const changed = new Set();
  list.forEach((entry, index) => entryWithin(entry, index, () => {
    if (!object(entry) || Object.keys(entry).length !== 3 || !['changeCheckId', 'actorId', 'after'].every(key => Object.hasOwn(entry, key))) bad('each entry is { changeCheckId, actorId, after } and nothing else');
    if (!LIFECYCLE_POLICIES.includes(entry.after)) bad('"after" must be "refused": the declared policy is that the application refuses the pre-change credential (an application whose sessions stay valid until they expire does not meet it)');
    if (typeof entry.actorId !== 'string' || !Object.hasOwn(target.actors, entry.actorId)) bad('"actorId" must name a declared actor');
    const actor = target.actors[entry.actorId];
    if (!actor.credentialEnv) bad('the changed actor needs a "credentialEnv": its pre-change credential is what the post-change checks re-send');
    if (changed.has(entry.actorId)) bad('an actor changes standing once per profile'); changed.add(entry.actorId);
    if (!identityControlsOf(entry.actorId).length) bad('the changed actor needs an identity control before the change (a required GET control whose json.equals names its identityValue)');
    // A post-change refusal counts only when the same credential was accepted on the protected routes before the change.
    if (!surfaceControlsOf(entry.actorId).length) bad('the changed actor needs a surface control before the change (a required GET allowed-use control on a protected route, other than its identity control), so its credential is shown to work where the post-change checks send it');
    const at = target.checks.findIndex(c => c.id === entry.changeCheckId);
    if (typeof entry.changeCheckId !== 'string' || at < 0) bad('"changeCheckId" must name a check of this profile');
    const change = target.checks[at];
    if (!applies(change) || !target.requiredControlIds.includes(change.id)) bad('the change check must be an applicable required allowed-use control, so a change that did not happen is never read as a refusal');
    // A self-change (the user signs out or revokes their own access) is sent by the changed actor: never a GET, which the
    // probe points would re-send as a surface control, and never another entry's change.
    if (change.actorId === entry.actorId) {
      if (change.method === 'GET') bad('a self-change check (sent by the changed actor) must use POST, PUT, PATCH or DELETE: required GET controls are re-sent at every probe point');
      if (list.some(other => other !== entry && other?.changeCheckId === entry.changeCheckId)) bad('a self-change check cannot be another entry\'s change check');
    }
    // A change confirms the post-change refusals only when the changer's own login is proven for it (actor-identity/5):
    // an actor with no identity control can never confirm a change.
    if (!identityControlsOf(change.actorId).length) bad('the change check must be sent by a credentialed actor with an identity control (a required GET control whose json.equals names its identityValue), so the change is attributed to a proven login');
    if ((target.observers ?? []).some(o => o?.witness?.actorId === entry.actorId)) bad('an observer witness cannot use the changed actor: its witness requests after the change would be refused');
    const after = postChangeChecks(target.checks, entry);
    if (!after.length) bad('declare at least one post-change check: a check of the changed actor after the change check that re-sends its pre-change credential');
    const refusal = lifecycleRefusalStatuses(actor);
    for (const check of after) {
      if (check.severity === 'control') bad(`post-change check "${check.id}" must expect the refusal, so it cannot be an allowed-use control: move the changed actor's controls before the change check`);
      const status = check.assertions.find(a => a.kind === 'status.equals' || a.kind === 'status.in');
      const expected = status.kind === 'status.in' ? status.expected : [status.expected];
      if (!expected.every(code => refusal.includes(code))) bad(`post-change check "${check.id}" must expect only the declared refusal (${refusal.join(', ')})`);
      if (!Array.isArray(check.effects) || !check.effects.some(e => e?.kind === 'effect.none')) bad(`post-change check "${check.id}" must pair its refusal with at least one effect.none clause: a refusal status does not show that nothing happened behind it`);
    }
  }));
  return list;
}
