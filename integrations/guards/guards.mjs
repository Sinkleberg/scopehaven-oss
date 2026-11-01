// Runtime guards: the checks an application installs at its own commit points and
// on its own reply path. They are the protective counterpart of two checks in the
// synthetic suite:
//   MIDTASK-01  work authorized before access was removed must not commit after
//   TRUTH-01    a reply must not tell the user an action succeeded when it did not
//
// The guards are pure and framework-neutral: no I/O, no credentials, no network.
// The application supplies small functions that read its own state, and the guards
// decide. Every decision goes to onDecision(entry) so the app can audit it.
//
// They do not replace the app's own authorization. They re-run the app's check at
// the moment that matters (immediately before an effect commits) and compare the
// outgoing reply with what the app actually recorded.
import { readReply } from '../claim-check/verify.mjs';

export const GUARD_SCHEMA = 'scopehaven-guards/1';
export const GUARD_DENIED = Object.freeze(['principal-inactive', 'grants-changed', 'permission-revoked', 'access-unreadable']);

export class GuardDenied extends Error {
  constructor(reason, detail = {}) { super(`Guard denied the commit: ${reason}.`); this.name = 'GuardDenied'; this.reason = reason; this.detail = detail; }
}
const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = v => (typeof v === 'string' ? v : null);
// A grants version has to be comparable by value across two reads. A string, a finite
// number or a bigint is; null, NaN and objects are not, and an app that returns one of
// those would either never detect a change (null) or deny every commit (objects, NaN).
// Those are contract errors, so the guard reports them as unreadable rather than
// silently disabling or silently blocking the check.
const usableVersion = v => typeof v === 'string' || typeof v === 'bigint' || (typeof v === 'number' && Number.isFinite(v));

// ---------------------------------------------------------------------------
// Access guard
//
// currentAccess(principalId) returns the app's own live view of a principal:
//   { active: boolean, grantsVersion: string|number|bigint, allows?(action, resource) }
// grantsVersion must be comparable by value; anything else is treated as unreadable.
// It must read the app's store on every call. A guard that caches is the defect.
//
//   const turn = await guard.beginTurn(principalId)     // at the start of the work
//   await guard.beforeCommit(turn, { action, resource }) // immediately before each effect
//
// beforeCommit throws GuardDenied when the principal is no longer active, the
// grants version moved since the turn began, the app now refuses this action, or
// the access could not be read at all. Unreadable access is a denial, never a pass.
export function createAccessGuard({ currentAccess, onDecision = () => {} }) {
  if (typeof currentAccess !== 'function') throw new TypeError('createAccessGuard needs currentAccess(principalId).');
  // Only turns this guard issued are accepted, so a copy of a turn cannot be handed
  // back with a different grantsVersion to defeat the one check that detects a change.
  const issued = new WeakSet();
  let turns = 0;
  const decide = entry => { const d = { guard: 'access', schema: GUARD_SCHEMA, ...entry }; try { onDecision(d); } catch { /* auditing must not break the guard */ } return d; };
  const read = async principalId => {
    let access;
    try { access = await currentAccess(principalId); } catch { access = null; }
    // `allows`, when present, has to be callable: an authz answer that crossed JSON and
    // arrived as data would otherwise skip the permission check without anyone noticing.
    const shaped = record(access) && typeof access.active === 'boolean' && usableVersion(access.grantsVersion)
      && (access.allows === undefined || typeof access.allows === 'function');
    return shaped ? access : null;
  };
  return {
    schema: GUARD_SCHEMA,
    // Capture what the work is authorized under. A principal that cannot start is denied here.
    async beginTurn(principalId) {
      if (!str(principalId)) throw new TypeError('beginTurn needs a principalId.');
      const access = await read(principalId);
      if (!access) { decide({ step: 'begin', principalId, allowed: false, reason: 'access-unreadable' }); throw new GuardDenied('access-unreadable', { principalId }); }
      if (!access.active) { decide({ step: 'begin', principalId, allowed: false, reason: 'principal-inactive' }); throw new GuardDenied('principal-inactive', { principalId }); }
      const turn = Object.freeze({ id: `turn-${++turns}`, principalId, grantsVersion: access.grantsVersion });
      issued.add(turn);
      decide({ step: 'begin', turnId: turn.id, principalId, allowed: true, grantsVersion: access.grantsVersion });
      return turn;
    },
    // Re-check immediately before the effect commits. Returns the fresh access on success.
    async beforeCommit(turn, { action, resource = null } = {}) {
      if (!record(turn) || !issued.has(turn)) throw new TypeError('beforeCommit needs the turn object beginTurn returned, not a copy of it.');
      if (!str(action)) throw new TypeError('beforeCommit needs an action name.');
      const at = { step: 'commit', turnId: turn.id, principalId: turn.principalId, action, resource };
      const access = await read(turn.principalId);
      const deny = reason => { decide({ ...at, allowed: false, reason }); throw new GuardDenied(reason, { ...at, authorizedUnder: turn.grantsVersion }); };
      if (!access) deny('access-unreadable');
      if (!access.active) deny('principal-inactive');
      // The work was authorized under one grants version; anything else is a different authority.
      if (access.grantsVersion !== turn.grantsVersion) deny('grants-changed');
      // A permission check that throws is an unreadable answer, not an allowed one.
      if (typeof access.allows === 'function') {
        let allowed;
        try { allowed = access.allows(action, resource); } catch { deny('access-unreadable'); }
        if (allowed !== true) deny('permission-revoked');
      }
      decide({ ...at, allowed: true, grantsVersion: access.grantsVersion });
      return access;
    },
  };
}

// Wrap an app's tool/effect map so every call passes beforeCommit first. The guard
// runs before the effect, so a denial means nothing was committed by that call.
// `resourceOf` names the resource for the audit trail and for allows().
export function guardCommits({ guard, turn, effects, resourceOf = () => null }) {
  if (!record(effects)) throw new TypeError('guardCommits needs an effects object.');
  // Own enumerable function entries only; each keeps `effects` as its receiver, so an
  // effect written as a method still reaches the object it belongs to.
  return Object.fromEntries(Object.entries(effects).filter(([, run]) => typeof run === 'function').map(([action, run]) => [action, async (...args) => {
    await guard.beforeCommit(turn, { action, resource: resourceOf(action, ...args) });
    return run.call(effects, ...args);
  }]));
}

// ---------------------------------------------------------------------------
// Claim guard
//
// Before a reply reaches the user, compare what it says with what the app recorded.
//   review({ claim, reply, record })
//     claim  the assistant's structured outcome, e.g. { status: 'done' }
//     reply  the text about to be sent
//     record what the app's own store shows:
//            { committed: true|false|null, effects?: number, expected?: number }
//            committed null means the app could not determine the outcome. When the
//            app counts effects, committed false with effects above zero is partial:
//            some of the work landed, so "nothing was changed" would itself be false.
//
// Verdicts:
//   supported     the reply, the claim and the record agree; the reply is unchanged
//   unsupported   the reply or claim asserts an outcome the record contradicts
//   unverifiable  the record could not be read, so success cannot be asserted
//   no-claim      the reply asserts no outcome the reader recognises; unchanged
//
// For unsupported and unverifiable the guard returns replacement text, so a false
// success never reaches the user. Replacing is the point: silently passing a wrong
// claim through is the TRUTH-01 defect. The replacement has to be true as well: the
// guard never tells the user nothing changed when the record shows that something did.
export const CLAIM_MESSAGES = Object.freeze({
  unsupported: 'That action was not completed. Nothing was changed, and I have not made the change I described.',
  partial: 'That action was not completed in full. Part of it was already applied, so please check the current state before trying it again.',
  unverifiable: 'I could not confirm whether that action completed. Please check before trying again, so it is not done twice.',
});
const ASSERTS_SUCCESS = stated => stated.done;
const ASSERTS_FAILURE = stated => stated.rejected || stated.failed;
// "queued", "pending approval": the work has not happened yet. On its own that is an
// outcome of its own; alongside a success claim it is ordinary wording ("processed;
// the receipt is queued"), so it only decides when nothing else was asserted.
const ASSERTS_PENDING = stated => stated.queued;

export function createClaimGuard({ onDecision = () => {}, messages = CLAIM_MESSAGES } = {}) {
  const text = { ...CLAIM_MESSAGES, ...(record(messages) ? messages : {}) };
  const decide = entry => { const d = { guard: 'claim', schema: GUARD_SCHEMA, ...entry }; try { onDecision(d); } catch { /* auditing must not break the guard */ } return d; };
  return {
    schema: GUARD_SCHEMA,
    // identifiers: ids the reply quotes (recipient, ticket), masked before reading so
    // an id such as "acct-no-7" is never read as wording.
    review({ claim = null, reply = '', record: outcome = null, identifiers = [] } = {}) {
      const stated = readReply(reply, identifiers);
      const claimed = record(claim) && typeof claim.status === 'string' ? claim.status : null;
      const committed = record(outcome) && typeof outcome.committed === 'boolean' ? outcome.committed : null;
      // Part of the work landed: not the claimed outcome, but not nothing either.
      const effects = record(outcome) && Number.isInteger(outcome.effects) ? outcome.effects : null;
      const partial = committed === false && effects !== null && effects > 0;
      const says = { success: ASSERTS_SUCCESS(stated) || claimed === 'done', failure: ASSERTS_FAILURE(stated) || ['rejected', 'failed'].includes(claimed),
        pending: ASSERTS_PENDING(stated) || claimed === 'queued' };
      const out = (verdict, reason, replacement) => {
        const result = { verdict, reason, stated, claimed, committed, partial, reply: replacement ?? reply, replaced: replacement !== undefined };
        decide({ step: 'reply', verdict, reason, claimed, committed, partial, replaced: result.replaced });
        return result;
      };
      // Nothing was asserted, so there is nothing to contradict.
      if (!says.success && !says.failure && !says.pending) return out('no-claim', 'reply-asserts-no-outcome');
      // A success claim needs a record that shows the effect.
      if (says.success) {
        if (partial) return out('unsupported', 'claimed-success-but-part-committed', text.partial);
        if (committed === false) return out('unsupported', 'claimed-success-but-nothing-committed', text.unsupported);
        if (committed === null) return out('unverifiable', 'outcome-not-readable', text.unverifiable);
        // The effect did commit, so the user must not be told nothing changed; saying it
        // both succeeded and failed still leaves them guessing, so ask them to check.
        if (says.failure) return out('unsupported', 'reply-asserts-both-outcomes', text.unverifiable);
        return out('supported', 'commit-recorded');
      }
      // "Still pending" is wrong once the effect landed: the user may ask for it again.
      if (says.pending && !says.failure) {
        if (committed === true) return out('unsupported', 'claimed-pending-but-effect-committed', text.unverifiable);
        if (committed === null) return out('unverifiable', 'outcome-not-readable', text.unverifiable);
        if (partial) return out('unsupported', 'claimed-pending-but-part-committed', text.partial);
        return out('supported', 'no-commit-recorded');
      }
      // A failure claim is wrong when the effect did land: the user may retry and double it.
      if (committed === true) return out('unsupported', 'claimed-failure-but-effect-committed', text.unverifiable);
      if (committed === null) return out('unverifiable', 'outcome-not-readable', text.unverifiable);
      if (partial) return out('unsupported', 'claimed-failure-but-part-committed', text.partial);
      return out('supported', 'no-commit-recorded');
    },
  };
}
