// Profiles for the owned practice app (app.mjs): one each for the lifecycle phase, typed
// captures (one check per creator role and actor role) and settlement. Every boundary
// clause is decided by the loopback egress recorder (a request-path observer held outside
// the app), so a clean build can pass under custody and a defect fails from records.
// observers: false declares an empty observer list (the missing-observer case: nothing can see the webhook).
import { HOOK_HOST, WITNESS_HOST, TOKEN_ENV } from './app.mjs';

const HOOK_PATHS = ['/hooks/alice/member', '/hooks/alice/admin', '/hooks/bob/member', '/hooks/bob/admin', '/hooks/carol/member', '/hooks/carol/admin', '/hooks/admin/member', '/hooks/admin/admin'];
const actor = name => ({ principalId: name, credentialEnv: TOKEN_ENV[name], identityValue: name });
const sink = sinkPort => ({ id: 'hooks', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: HOOK_HOST, paths: HOOK_PATHS }],
  witness: { actorId: 'admin', method: 'GET', path: '/api/ping', host: WITNESS_HOST }, witnessWaitMs: 3000, quietMs: 150, settleMs: 300 });
const hook = path => ({ source: 'http-egress', operation: 'send', name: HOOK_HOST, resource: `POST ${path}` });
// Every webhook a deleter's actions send (src/http-pairing.mjs): a forbidden cell whose exact route only a forbidden action
// would produce (bob acting on an administrator's note) is pinned to the deleter's prefix, which bob's own allowed delete pairs.
const hookPrefix = deleter => ({ source: 'http-egress', operation: 'send', name: HOOK_HOST, resource: { prefix: `POST /hooks/${deleter}/` } });
const whoami = (id, user, extra = {}) => ({ id, title: `${user} is signed in`, category: 'Identity', severity: 'control', actorId: user, method: 'GET', path: '/api/me', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: user }], ...extra });
// A surface control (actor-identity/4): an allowed GET on a protected route, re-sent in the actor's brackets. It does not
// assert the identity value, or it would be another identity control.
const ownNotes = (id, user) => ({ id, title: `${user} lists her own notes`, category: 'Allowed use', severity: 'control', actorId: user, method: 'GET', path: '/api/notes', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/count', expected: true }] });
const createNote = (id, user, name) => ({ id, title: `${user} creates a note`, category: 'Setup', severity: 'control', actorId: user, method: 'POST', path: '/api/notes', body: { text: 'synthetic note' },
  evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }, { kind: 'json.exists', pointer: '/id', expected: true }], ...(name ? { capture: { [name]: { pointer: '/id', type: 'id' } } } : {}) });
// effects: the clauses when they are not the one webhook of `path` (allowed: effect.count 1; forbidden: effect.none).
const deleteNote = (id, user, note, createdBy, { allowed, path, title, effects }) => ({ id, title, category: allowed ? 'Allowed use' : 'Object access', severity: allowed ? 'control' : 'high', actorId: user, method: 'POST',
  path: `/api/notes/{{${note}}}/delete`, body: {}, evidenceRequirement: allowed ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: allowed ? 200 : 403 }],
  effects: effects ?? [allowed ? { kind: 'effect.count', select: hook(path), expected: 1 } : { kind: 'effect.none', select: hook(path) }], precondition: [{ name: note, type: 'id', createdBy }] });
// Bob's own allowed delete: the positive match (src/http-pairing.mjs) for bob's forbidden cells, on his exact member route
// and on his prefix. It comes before the forbidden cells, so its webhook is never a late effect of theirs.
const bobDeleteOwn = id => deleteNote(id, 'bob', 'bobNoteA', 'bob', { allowed: true, path: '/hooks/bob/member', title: 'A member deletes his own note',
  effects: [{ kind: 'effect.count', select: hook('/hooks/bob/member'), expected: 1 }, { kind: 'effect.count', select: hookPrefix('bob'), expected: 1 }] });
const target = (id, name, origin, sinkPort, observers, checks, extra = {}) => ({ id, name, applicationId: 'core-practice-desk', origin, buildLabel: 'practice', contextId: 'synthetic-desk',
  actors: { admin: actor('admin'), alice: actor('alice'), bob: actor('bob'), carol: actor('carol') }, observers: observers === false ? [] : [sink(sinkPort)],
  requiredControlIds: checks.filter(c => c.severity === 'control').map(c => c.id), checks, ...extra });

// Lifecycle: the administrator suspends carol; carol's pre-change credential must then be refused,
// with nothing sent behind the refusal, while bob (unchanged) keeps working.
export function lifecycleProfile({ origin, sinkPort, observers = true }) {
  const checks = [
    whoami('ADMIN-WHOAMI', 'admin'), whoami('BOB-WHOAMI', 'bob'),
    whoami('CAROL-WHOAMI', 'carol', { capture: { carolId: { pointer: '/id', type: 'id' } } }), ownNotes('CAROL-NOTES', 'carol'),
    createNote('CAROL-NOTE-1', 'carol', 'carolNote1'), createNote('CAROL-NOTE-2', 'carol', 'carolNote2'),
    deleteNote('CAROL-DELETE-OWN', 'carol', 'carolNote1', 'carol', { allowed: true, path: '/hooks/carol/member', title: 'Carol deletes her own note before the change' }),
    { id: 'ADMIN-SUSPEND-CAROL', title: 'The administrator suspends carol', category: 'Account change', severity: 'control', actorId: 'admin', method: 'POST', path: '/api/admin/users/{{carolId}}/suspend', body: {},
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/status', expected: 'suspended' }], precondition: [{ name: 'carolId', type: 'id', createdBy: 'carol' }] },
    whoami('BOB-WHOAMI-AFTER', 'bob'), createNote('BOB-NOTE-AFTER', 'bob'),
    { id: 'CAROL-REUSE-ME', title: 'Carol\'s pre-change credential is refused after the suspension', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/api/me',
      evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: hook('/hooks/carol/member') }] },
    { ...deleteNote('CAROL-REUSE-DELETE', 'carol', 'carolNote2', 'carol', { allowed: false, path: '/hooks/carol/member', title: 'Carol\'s pre-change credential cannot delete after the suspension' }),
      category: 'Lifecycle', assertions: [{ kind: 'status.in', expected: [401, 403] }] },
  ];
  return target('desk-lifecycle', 'Practice desk: lifecycle', origin, sinkPort, observers, checks, { lifecycle: [{ changeCheckId: 'ADMIN-SUSPEND-CAROL', actorId: 'carol', after: 'refused' }] });
}

// Self-change lifecycle: carol signs herself out; her pre-change credential must then be refused, with nothing
// sent behind the refusal, while bob (unchanged) keeps working. The sign-out answer names who was signed out, a
// predicate only an accepted credential produces.
export function selfLifecycleProfile({ origin, sinkPort, observers = true }) {
  const base = lifecycleProfile({ origin, sinkPort, observers });
  const signOut = { id: 'CAROL-SIGN-OUT', title: 'Carol signs herself out', category: 'Account change', severity: 'control', actorId: 'carol', method: 'POST', path: '/api/sign-out', body: {},
    evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/signedOut', expected: true }, { kind: 'json.equals', pointer: '/user', expected: 'carol' }] };
  const checks = base.checks.map(check => check.id === 'ADMIN-SUSPEND-CAROL' ? signOut : check).map(check => check.id.startsWith('CAROL-REUSE')
    ? { ...check, title: check.title.replace('after the suspension', 'after she signed out') } : check);
  return target('desk-self-lifecycle', 'Practice desk: self-change lifecycle', origin, sinkPort, observers, checks, { lifecycle: [{ changeCheckId: 'CAROL-SIGN-OUT', actorId: 'carol', after: 'refused' }] });
}

// Creator versus actor: one check per (creator role, actor role) cell, on notes captured from their creators.
export function creatorProfile({ origin, sinkPort, observers = true }) {
  const checks = [
    whoami('ADMIN-WHOAMI', 'admin'), whoami('ALICE-WHOAMI', 'alice'), whoami('BOB-WHOAMI', 'bob'), ownNotes('ADMIN-NOTES', 'admin'), ownNotes('BOB-NOTES', 'bob'),
    createNote('ALICE-NOTE-A', 'alice', 'aliceNoteA'), createNote('ALICE-NOTE-B', 'alice', 'aliceNoteB'), createNote('ALICE-NOTE-C', 'alice', 'aliceNoteC'),
    createNote('ADMIN-NOTE-A', 'admin', 'adminNoteA'), createNote('ADMIN-NOTE-B', 'admin', 'adminNoteB'), createNote('BOB-NOTE-A', 'bob', 'bobNoteA'),
    deleteNote('CELL-MEMBER-BY-OWNER', 'alice', 'aliceNoteA', 'alice', { allowed: true, path: '/hooks/alice/member', title: 'A member deletes a note she created' }),
    deleteNote('CELL-ADMIN-BY-ADMIN', 'admin', 'adminNoteA', 'admin', { allowed: true, path: '/hooks/admin/admin', title: 'An administrator deletes a note an administrator created' }),
    deleteNote('CELL-MEMBER-BY-ADMIN', 'admin', 'aliceNoteB', 'alice', { allowed: true, path: '/hooks/admin/member', title: 'An administrator deletes a note a member created' }),
    bobDeleteOwn('BOB-DELETE-OWN'),
    deleteNote('CELL-MEMBER-BY-OTHER', 'bob', 'aliceNoteC', 'alice', { allowed: false, path: '/hooks/bob/member', title: 'A member cannot delete another member\'s note' }),
    // The last cell: only a forbidden action would send to /hooks/bob/admin, so the absence is pinned to bob's prefix (paired above).
    deleteNote('CELL-ADMIN-BY-MEMBER', 'bob', 'adminNoteB', 'admin', { allowed: false, path: '/hooks/bob/admin', title: 'A member cannot delete a note an administrator created', effects: [{ kind: 'effect.none', select: hookPrefix('bob') }] }),
  ];
  return target('desk-creator', 'Practice desk: creator versus actor', origin, sinkPort, observers, checks);
}

// Settlement: a refused delete that still commits sends its webhook after its window closed.
export function settlementProfile({ origin, sinkPort, observers = true }) {
  const checks = [
    whoami('ADMIN-WHOAMI', 'admin'), whoami('ALICE-WHOAMI', 'alice'), whoami('BOB-WHOAMI', 'bob'), ownNotes('BOB-NOTES', 'bob'),
    createNote('ALICE-NOTE-A', 'alice', 'aliceNoteA'), createNote('ALICE-NOTE-B', 'alice', 'aliceNoteB'), createNote('ADMIN-NOTE-A', 'admin', 'adminNoteA'), createNote('BOB-NOTE-A', 'bob', 'bobNoteA'),
    bobDeleteOwn('BOB-DELETE-OWN'),
    deleteNote('ALICE-DELETE-OWN', 'alice', 'aliceNoteA', 'alice', { allowed: true, path: '/hooks/alice/member', title: 'A member deletes her own note' }),
    // Pinned to bob's prefix (only a forbidden action sends to /hooks/bob/admin); the later cell keeps its exact member route.
    deleteNote('BOB-DELETE-ADMIN-NOTE', 'bob', 'adminNoteA', 'admin', { allowed: false, path: '/hooks/bob/admin', title: 'A member cannot delete an administrator\'s note', effects: [{ kind: 'effect.none', select: hookPrefix('bob') }] }),
    createNote('ALICE-NOTE-C', 'alice'),
    deleteNote('BOB-DELETE-MEMBER-NOTE', 'bob', 'aliceNoteB', 'alice', { allowed: false, path: '/hooks/bob/member', title: 'A member cannot delete another member\'s note' }),
    // The administrator's last allowed GET: the only request after the last effect window and before the final mark that
    // no probe point sends earlier (the tail trigger below).
    ownNotes('ADMIN-NOTES-END', 'admin'),
  ];
  return target('desk-settlement', 'Practice desk: settlement', origin, sinkPort, observers, checks);
}
// When the refused delete's late webhook goes out (app.mjs refusedCommit), and where it lands.
export const LATE_TRIGGERS = Object.freeze({
  gap: { method: 'POST', path: '/api/notes', user: 'alice', creatorRole: 'admin' },          // ALICE-NOTE-C: between two effect windows
  'next-window': { method: 'POST', pathPrefix: '/api/notes/', user: 'bob', creatorRole: 'admin' }, // BOB-DELETE-MEMBER-NOTE's own window
  tail: { method: 'GET', path: '/api/notes', user: 'admin', creatorRole: 'admin' },           // ADMIN-NOTES-END: after the last window, before the final mark
});
export const manifest = profile => ({ schemaVersion: 1, targets: [profile] });
