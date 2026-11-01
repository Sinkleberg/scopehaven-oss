// The starter profile: two credentialed actors in two declared tenants plus an anonymous actor, following
// docs/ONBOARDING.md ("Connecting a local application you own") and the minimal profile there.
//
//   A-WHOAMI, B-WHOAMI          identity controls on the session-derived who-am-I route (json.equals on the probed pointer)
//   A-OWN-RECORD, B-OWN-RECORD  allowed-use controls (each actor opens its own record, with a json.equals on a field that
//                               names the record when its body has one); also each actor's surface control
//   B-READS-A-RECORD            prohibition: B opens A's record              twin: A-OWN-RECORD
//   A-READS-B-RECORD            prohibition: A opens B's record              twin: B-OWN-RECORD
//   ANON-READS-A-RECORD         prohibition: a signed-out request for A's record   twin: A-OWN-RECORD
//   B-READS-A-RECORD-BACKEND    the same prohibition, requiring backend evidence: INCONCLUSIVE until an observer is wired
//
// How a prohibition is judged. Many apps refuse another tenant's record with 401, 403 or 404, and the check then expects
// one of those. Others answer 2xx and filter the row away: PostgREST and Supabase answer a row that row-level security
// hides with 200 and an empty list. A status check would call that a cross-tenant read, a false FAIL. So when the
// prohibited read answered 2xx during discovery, the check expects that status and judges the body instead:
//   - an empty list keeps that shape (json.exists /0 false; for a list wrapped in an object, such as { data: [] },
//     json.exists /data/0 false) and null stays null (json.equals null), so any populated answer later fails,
//     whichever fields it holds;
//   - another 2xx body without the owner's values, with two identities: json.noForeignValues over the whole body against
//     each tenant's own record values, declared in tenantValues from the record as served to its owner. The signed-out
//     actor is a tenant of its own whose one declared value is a marker that occurs nowhere. With one identity (assess
//     refuses a single-identity profile that declares tenantValues) it keeps the refusal statuses, and init says so;
//   - a 2xx that already held the owner's values is a leak seen during discovery: it is reported before the run as a
//     candidate FAIL and keeps the refusal statuses, so the run decides FAIL.
//
// Every check is a GET: the starter run changes nothing in the app.

export const ID = /^[A-Za-z0-9_-]{1,80}$/;
const status = expected => ({ kind: 'status.equals', expected });
const statusIn = expected => ({ kind: 'status.in', expected });
const ok = s => Number.isInteger(s) && s >= 200 && s < 300;

// Refusal statuses for a credentialed actor reading another tenant's record, and for a signed-out request. A declared
// sign-in redirect (a 3xx the app sent a signed-out probe) counts as a refusal of the signed-out request.
export const CROSS_TENANT_REFUSAL = Object.freeze([403, 404]);
export const anonymousRefusal = redirect => redirect ? [401, 403, 404, redirect] : [401, 403, 404];
export const SIGNED_OUT_TENANT = 'signed-out';
export const SIGNED_OUT_MARKER = 'scopehaven-signed-out-holds-no-records';

// The assertions for one prohibition from what its read answered during discovery. Returns { assertions, judged } where
// judged says how ('refusal', 'content', 'empty-list', 'null', 'refusal-unjudged-2xx').
export function prohibitionAssertions(read, refusal, { tenantScoped }) {
  if (!read || !ok(read.status)) return { assertions: [statusIn(refusal)], judged: 'refusal' };
  // A 2xx that already carried the owner's values is a leak seen during discovery: the check keeps the refusal statuses so
  // the run decides FAIL on the status, whatever the content rules (an echoed id reads inconclusive) would say.
  if (read.leaked) return { assertions: [statusIn(refusal)], judged: 'refusal-leak-seen' };
  // An empty answer keeps its shape: any populated answer later fails, whichever fields it holds.
  if (read.shape === 'empty-array') return { assertions: [status(read.status), { kind: 'json.exists', pointer: '/0', expected: false }], judged: 'empty-list' };
  if (read.shape === 'null') return { assertions: [status(read.status), { kind: 'json.equals', pointer: '', expected: null }], judged: 'null' };
  // A wrapped list could later come back in another shape (the record itself, without the wrapper), so with two
  // identities the other tenant's values are judged too.
  if (read.shape === 'empty-wrapped') return { assertions: [status(read.status), { kind: 'json.exists', pointer: `${read.listPointer}/0`, expected: false },
    ...(tenantScoped ? [{ kind: 'json.noForeignValues', pointer: '' }] : [])], judged: 'empty-list' };
  if (tenantScoped) return { assertions: [status(read.status), { kind: 'json.noForeignValues', pointer: '' }], judged: 'content' };
  return { assertions: [statusIn(refusal)], judged: 'refusal-unjudged-2xx' };
}

export function buildProfile({ id, name, origin, buildLabel = 'local copy', contextId = 'synthetic-seed-1', whoami, identities, records, reads = {}, slot, signInRedirectStatus = null }) {
  if (!ID.test(id)) throw new Error('The target id is 1 to 80 letters, digits, "_" or "-".');
  const two = identities.length === 2;
  // tenantValues need each credentialed tenant's own record values; without them every prohibition falls back to the
  // single-identity rules above.
  const tenantScoped = two && records.a.values?.length > 0 && records.b.values?.length > 0;
  const actor = (identity, tenant) => ({
    principalId: identity.principalId, tenantId: tenant, role: 'member', credentialEnv: identity.credentialEnv,
    ...(slot.kind === 'cookie' ? { credentialCookie: slot.name } : slot.kind === 'header' ? { credentialHeader: slot.name } : {}),
    identityValue: identity.identityValue,
    ...(signInRedirectStatus ? { signInRedirectStatus } : {}),
  });
  const actors = { a: actor(identities[0], 'tenant-a'), ...(two ? { b: actor(identities[1], 'tenant-b') } : {}),
    anonymous: { principalId: 'anonymous', ...(tenantScoped ? { tenantId: SIGNED_OUT_TENANT } : {}) } };
  const check = (checkId, title, category, severity, actorId, path, assertions, evidenceRequirement = 'response') =>
    ({ id: checkId, title, category, severity, actorId, method: 'GET', path, evidenceRequirement, assertions });
  const whoamiCheck = (key, identity) => check(`${key}-WHOAMI`, `Identity ${key}'s session names identity ${key}`, 'Identity', 'control', key.toLowerCase(), whoami.path,
    [status(whoami.status ?? 200), { kind: 'json.equals', pointer: whoami.pointer, expected: identity.identityValue }]);
  const ownRecord = (key, record) => check(`${key}-OWN-RECORD`, `Identity ${key} opens its own record (allowed use)`, 'Access', 'control', key.toLowerCase(), record.path,
    [status(record.ownerStatus), ...(record.predicate ? [{ kind: 'json.equals', pointer: record.predicate.pointer, expected: record.predicate.value }] : [])]);
  const checks = [whoamiCheck('A', identities[0])];
  const required = ['A-WHOAMI'];
  const twins = [], judged = {};
  if (two) { checks.push(whoamiCheck('B', identities[1])); required.push('B-WHOAMI'); }
  checks.push(ownRecord('A', records.a)); required.push('A-OWN-RECORD');
  const prohibition = (checkId, title, actorId, path, read, refusal, evidence = 'response') => {
    const { assertions, judged: how } = prohibitionAssertions(read, refusal, { tenantScoped });
    judged[checkId] = how;
    checks.push(check(checkId, title, 'Access', 'high', actorId, path, assertions, evidence));
  };
  if (two) {
    checks.push(ownRecord('B', records.b)); required.push('B-OWN-RECORD');
    prohibition('B-READS-A-RECORD', 'Identity B cannot open identity A\'s record', 'b', records.a.path, reads.bReadsA, CROSS_TENANT_REFUSAL);
    twins.push({ prohibition: 'B-READS-A-RECORD', allowedUse: 'A-OWN-RECORD' });
  }
  prohibition('A-READS-B-RECORD', two ? 'Identity A cannot open identity B\'s record' : 'Identity A cannot open a record of another tenant', 'a', records.b.path, reads.aReadsB, CROSS_TENANT_REFUSAL);
  twins.push({ prohibition: 'A-READS-B-RECORD', allowedUse: two ? 'B-OWN-RECORD' : null });
  prohibition('ANON-READS-A-RECORD', 'A signed-out request cannot open identity A\'s record', 'anonymous', records.a.path, reads.anonReadsA, anonymousRefusal(records.a.anonymousRedirect));
  twins.push({ prohibition: 'ANON-READS-A-RECORD', allowedUse: 'A-OWN-RECORD' });
  const [backendActor, backendPath, backendTwin, backendRead] = two ? ['b', records.a.path, 'A-OWN-RECORD', reads.bReadsA] : ['a', records.b.path, null, reads.aReadsB];
  prohibition(`${backendActor.toUpperCase()}-READS-${two ? 'A' : 'B'}-RECORD-BACKEND`, 'The foreign record is not read inside the app (needs an observer)', backendActor, backendPath,
    backendRead, CROSS_TENANT_REFUSAL, 'backend');
  twins.push({ prohibition: checks.at(-1).id, allowedUse: backendTwin });
  const profile = { id, name, applicationId: id, origin, buildLabel, contextId, actors, requiredControlIds: required, checks };
  if (tenantScoped) {
    // Only checks that judge content use them; with every prohibition refused by status, none is declared (the loader
    // refuses tenantValues no check uses).
    if (checks.some(c => c.assertions.some(a => a.kind === 'json.noForeignValues'))) {
      profile.tenantValues = { tenants: {
        'tenant-a': { identifiers: records.a.values },
        'tenant-b': { identifiers: records.b.values },
        [SIGNED_OUT_TENANT]: { identifiers: [SIGNED_OUT_MARKER] },
      } };
    } else delete actors.anonymous.tenantId;
  }
  return { profile, twins, judged, tenantScoped: Boolean(profile.tenantValues) };
}
