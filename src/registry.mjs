import { open } from 'node:fs/promises';
import { webhookSuiteViews } from './webhook-driver.mjs';
import { constants } from 'node:fs';
import { TARGETS, SUITE, CATALOG_IDENTITY_SCHEMA, CATALOG_OBSERVER_TYPES } from './suite.mjs';
import { runAssessment } from './runner.mjs';
import { runHttpAssessment, credentialReadiness } from './http-connector.mjs';
import { validateTargetFile, contractDigest, ASSERTION_SCHEMA_VERSION, identityControlPlan, COOKIE_NAME_PATTERN, IDENTITY_EVIDENCE_SCHEMA, zeroRowDeclaration } from './contracts.mjs';
import { readBackDeclarations, readBackSuiteView } from './http-readback.mjs';
import { declaredObserverRecord, declaredClaim, observerInstanceId } from './http-effects.mjs';
import { correlationRecorded } from './egress-rules.mjs';
import { CHECKS as REFUND_CHECKS } from '../integrations/temporal-contracts/contract.mjs';
import { REFUND_TARGETS, refundTarget } from '../integrations/temporal-contracts/targets.mjs';
import { captureUsesOf } from './http-captures.mjs';
import { recordClasses, staticRecordPartners, staticRestsOnRelated } from './http-rests-on.mjs';
import { tenantValueCounts } from './tenant-values.mjs';
import { mirrorLimitStatuses } from './two-identities.mjs';
import { digest } from './domain.mjs';
// The build that made a run (security review F9), stamped here so no evaluator's own files change.
import { stampProducer } from './producer.mjs';
import { unpairedSelectors, unguardedAbsences } from './http-pairing.mjs';
import { appLogRecords } from './app-log-verdicts.mjs';
import { guardObserverFactory } from './authorization.mjs';
// Watch-first drafted lines (integrations/watch-first/lines.mjs): a profile with an unapproved one is refused before validation.
import { admitDraftedLines } from '../integrations/watch-first/lines.mjs';
const usesPacks = input => input !== null && typeof input === 'object' && Array.isArray(input.targets) && input.targets.some(t => t !== null && typeof t === 'object' && Object.hasOwn(t, 'packs'));
let refundModule;
const loadRefund = () => refundModule ??= import('../integrations/temporal-contracts/runner.mjs');

export async function loadProfiles(file) {
  if (!file) return [];
  let handle;
  try { handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch { throw new Error('Target configuration must be a readable regular JSON file, not a symlink.'); }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > 2097152n) throw new Error('Target configuration must be a regular JSON file no larger than 2 MiB.');
    const bytes = Buffer.alloc(2097153); let size = 0;
    while (size < bytes.length) {
      const part = await handle.read(bytes, size, bytes.length - size, size);
      if (!part.bytesRead) break;
      size += part.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (size > 2097152 || BigInt(size) !== after.size || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('Target configuration changed or exceeds its size limit.');
    let input;
    try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size))); } catch { throw new Error('Target configuration contains invalid JSON or UTF-8.'); }
    const admitted = admitDraftedLines(input);
    // Check packs (integrations/packs-v2/expand.mjs): loaded only for a profile that references one; refused unless every
    // pack matches scopehaven.lock beside the profile and every pack check is shown able to fail.
    return validateTargetFile(usesPacks(admitted) ? await (await import('../integrations/packs-v2/expand.mjs')).expandPacks(admitted, { profileFile: file }) : admitted);
  } finally { await handle.close(); }
}
// An http-audit observer reads the application's audit log with its own credential. A target whose
// observer credential is missing or invalid cannot be assessed, so it is not ready. This is the
// transport's credential rule (credentialReadiness) applied to each such observer, offline: no
// observer is created and nothing connects. Reasons name the environment references, never values.
// The CLI's check-config and --list, and the dashboard (registry.list), all read readiness here.
export function withAuditCredentialReadiness(target, profile, env = process.env) {
  let ready = true;
  const missing = new Set(target.missingCredentialRefs || []);
  for (const observer of profile?.observers || []) {
    if (observer.type !== 'http-audit' || (observer.credentialEnv === undefined && observer.credentialCookie === undefined)) continue;
    const hasRef = observer.credentialEnv !== undefined; // loadProfiles already validates the reference namespace.
    const validCookie = observer.credentialCookie === undefined || (typeof observer.credentialCookie === 'string' && COOKIE_NAME_PATTERN.test(observer.credentialCookie));
    const credentialReady = hasRef && validCookie && credentialReadiness({ actors: { audit: observer }, checks: [{ actorId: 'audit' }] }, env).ready;
    if (!credentialReady) {
      ready = false;
      if (hasRef) missing.add(observer.credentialEnv);
    }
  }
  return ready ? target : { ...target, available: false, ready: false, readinessReason: 'One or more audit observer credentials are missing or invalid.',
    missingCredentialRefs: [...missing], description: `HTTP response contracts · ${profile.checks.length} checks. Required credentials are missing or invalid.` };
}

export function createRegistry({ profiles = [], env = process.env } = {}) {
  const validated = profiles.length ? validateTargetFile({ schemaVersion: 1, targets: profiles }) : [];
  if (validated.some(p => TARGETS.some(t => t.id === p.id) || refundTarget(p.id))) throw new Error('A configured target cannot replace a built-in demo identifier.');
  const byId = new Map(validated.map(p => [p.id, p]));
  const refundSuites = new Map();
  const refundSuiteFor = async id => {
    const suite = await (await loadRefund()).currentRefundSuite(id);
    refundSuites.set(id, suite);
    return suite;
  };
  const list = () => [
    ...REFUND_TARGETS.map(({variant,...t})=>({...t, available:true, checksTotal:REFUND_CHECKS.length})),
    ...TARGETS.map(t => ({ ...t, available: true, kind: 'owned-demo', evidenceOrigin: 'synthetic-local-http', checksTotal: SUITE.checks.length })),
    // unpairedSelectors (src/http-pairing.mjs): absence selectors with no allowed-use twin; their rows read inconclusive (selector-unpaired)
    // unless a deciding observer's run-time resource vocabulary vouches for the resource pin, which this static list cannot see.
    // unguardedAbsences (FIX-07): unpinned absences of a boundary check that expects a success status and has no positive clause,
    // whose actor has no required allowed-use control with a positive effect; their passes read inconclusive (allowed-use-not-declared).
    ...validated.map(p => { const readiness = credentialReadiness(p, env), unpaired = unpairedSelectors(p), unguarded = unguardedAbsences(p); return withAuditCredentialReadiness({ id: p.id, name: p.name, build: p.buildLabel, kind: 'http-contract', evidenceOrigin: 'local-http-response', checksTotal: p.checks.length, available: readiness.ready, ...readiness, ...(unpaired.length ? { unpairedSelectors: unpaired } : {}), ...(unguarded.length ? { unguardedAbsences: unguarded } : {}), description: `HTTP response contracts · ${p.checks.length} checks. ${readiness.ready ? 'Credentials configured; connection not yet tested.' : 'Required credentials are missing or invalid.'}` }, p, env); }),
  ];
  const registry = {
    list, hasProfiles: validated.length > 0,
    has: id => TARGETS.some(t => t.id === id) || Boolean(refundTarget(id)) || byId.has(id),
    // beforeRequest (CMP-ROE-01): called immediately before every request a configured target's run sends, on whichever
    // transport the connector uses (the loopback one or a remote target's pinned HTTPS one, src/http-connector.mjs), and
    // every call it makes to a declared observer except stop (an authorization window guard, src/authorization.mjs
    // windowGuard and guardObserver); when it throws, that request is not sent and that observer reads nothing.
    // remote (H1 step 3): what the authorization record allows a remote target's transport to dial (src/remote-target.mjs).
    // A refund run names no build in its core, because its record is closed: it is frozen at finalization. Its signed envelope still names the signing build.
    run: async (id, { beforeRequest, remote } = {}) => {
      if (refundTarget(id)) return (await loadRefund()).runRefundAssessment(id);
      if (!byId.has(id)) return stampProducer(await runAssessment(id));
      const profile = byId.get(id), options = { env, ...(remote ? { remote } : {}) };
      if (!beforeRequest) return stampProducer(await runHttpAssessment(profile, options));
      const observerFactory = Object.hasOwn(profile, 'observers') ? guardObserverFactory((await import('../integrations/observers/factory.mjs')).buildObservers, beforeRequest) : undefined;
      return stampProducer(await runHttpAssessment(profile, { ...options, beforeRequest, ...(observerFactory ? { observerFactory } : {}) }));
    },
    currentSuite: async id => {
      if (refundTarget(id)) return refundSuiteFor(id);
      return registry.exportSuite(id);
    },
    exportSuite: id => {
      if (refundTarget(id)) { if (!refundSuites.has(id)) throw new Error('refund-source-not-ready'); return refundSuites.get(id); }
      if (!id || TARGETS.some(t => t.id === id)) return { ...SUITE, scope: 'Owned fixture, deterministic policies; not a general customer connector.', runnableWith: './scopehaven assess --target demo-repaired' };
      const p = byId.get(id); if (!p) throw Object.assign(new Error('Unknown target.'), { status: 400 });
      const identity = identityControlPlan(p);
      // actor-identity/6 (src/http-rests-on.mjs): ranks and control ids only, never a pointer, a value or a path.
      const recordRanks = recordClasses(p), recordPartners = staticRecordPartners(p), restsOnRelated = staticRestsOnRelated(p);
      // Typed captures: names and types only (never pointers or values); a use names its capturing check and creator.
      const captureSource = new Map(p.checks.flatMap(c => Object.entries(c.capture ?? {}).map(([name, spec]) => [name, { name, type: spec.type, createdBy: c.actorId, captureCheckId: c.id }])));
      return { id: `${p.id}-contracts`, targetId: p.id, applicationId: p.applicationId, version: ASSERTION_SCHEMA_VERSION, evidenceOrigin: 'local-http-response', hash: contractDigest(p),
        scope: 'Definition summary only; private request bodies, expected values, actor credentials and endpoints are omitted.', requiredControlIds: p.requiredControlIds,
        checks: p.checks.map(c => ({ id: c.id, title: c.title, category: c.category, severity: c.severity, evidenceRequirement: c.evidenceRequirement, method: c.method, ...(c.applicability ? { applicability: c.applicability } : {}), ...(webhookSuiteViews(p).has(c.id) ? { webhook: webhookSuiteViews(p).get(c.id) } : {}), assertionKinds: c.assertions.map(a => a.kind),
          // Actor alias and credential mode only; never the credential reference, name or value.
          actorId: c.actorId, credentialMode: !p.actors[c.actorId].credentialEnv ? 'none' : p.actors[c.actorId].credentialHeader ? 'header' : p.actors[c.actorId].credentialCookie ? 'cookie' : 'bearer',
          // Identity controls: which predicate (by position) proves the login and which statuses count as refusals; never the identity value.
          ...(identity.get(c.actorId)?.identityControls.includes(c.id) ? { identityControl: true, identityPredicate: identity.get(c.actorId).predicateIndex[c.id], refusalStatuses: identity.get(c.actorId).refusalStatuses, refusesWith401: identity.get(c.actorId).refusesWith401 } : {}),
          // Declared effects bind the run to what its observers had to decide.
          ...(c.effects ? { effects: c.effects } : {}),
          // Claim rules bind the run by digest here. The declared rules themselves (phrases and values included) are
          // stored in each check's sealed trace (src/http-effects.mjs effectTrace, data.claims) and exported with it.
          ...(c.claims ? { claimsDigest: digest(c.claims.map(declaredClaim)) } : {}),
          ...(c.capture ? { captures: Object.entries(c.capture).map(([name, spec]) => ({ name, type: spec.type })) } : {}),
          ...(captureUsesOf(c).length ? { captureUses: captureUsesOf(c).map(name => captureSource.get(name)) } : {}),
          ...(c.precondition ? { precondition: c.precondition } : {}),
          // rls-zero-row (NC9 item 3): the declared write of an allowed-use control and its capturing observer (table, operation and
          // instance id only), so a run's sealed zero-row record is required exactly here.
          ...(zeroRowDeclaration(p, c) ? { zeroRow: zeroRowDeclaration(p, c) } : {}),
          // Read-back (src/http-readback.mjs): the tables that judge this check, by instance id, table and declaration digest.
          ...(readBackDeclarations(p, c) ? { readBack: readBackDeclarations(p, c).map(readBackSuiteView) } : {}),
          // actor-identity/6: every check's record predicates as [index, field rank, value rank]; a required control's
          // declared partners; and a check's restsOn ids with the required controls its route relation relates to it.
          recordPredicates: recordRanks.get(c.id) ?? [],
          ...(recordPartners.has(c.id) ? { recordPartners: recordPartners.get(c.id) } : {}),
          ...(c.restsOn ? { restsOn: c.restsOn, restsOnRelated: restsOnRelated.get(c.id) ?? [] } : {}),
          // A generated mirror (src/two-identities.mjs) names its source, so a run's mirror rows are bound to exactly these checks.
          ...(Object.hasOwn(c, 'mirrorOf') ? { mirrorOf: c.mirrorOf } : {}) })),
        // The mirror phase (NC11): the rate-limit statuses the runs' mirror rows are read under, only for a profile with generated mirrors.
        ...(p.checks.some(c => Object.hasOwn(c, 'mirrorOf')) ? { mirrorPhase: { rateLimitStatuses: mirrorLimitStatuses(p) } } : {}),
        // The identity rules (actor-identity/6) the runs of this suite follow, and a digest of the declared principals
        // (alias -> principalId) its absence selectors are paired against (src/http-pairing.mjs); the identifiers stay private.
        identitySchema: IDENTITY_EVIDENCE_SCHEMA,
        // The database observers whose runs carry a catalog identity (N13, src/catalog-identity.mjs), by instance, and its schema.
        ...((p.observers ?? []).some(o => CATALOG_OBSERVER_TYPES.includes(o.type)) ? { catalogSchema: CATALOG_IDENTITY_SCHEMA,
          catalogObservers: p.observers.filter(o => CATALOG_OBSERVER_TYPES.includes(o.type)).map(o => observerInstanceId(o.type, o.id)) } : {}),
        principalsDigest: digest(Object.fromEntries(Object.entries(p.actors).map(([alias, actor]) => [alias, actor.principalId]))),
        // Lifecycle: which allowed-use control changes which actor's standing, and the declared policy after it.
        ...(p.lifecycle ? { lifecycle: p.lifecycle } : {}),
        // json.noForeignValues: per-tenant value counts, the attributesAlone policy and actor tenant positions; never the values.
        ...(p.tenantValues ? { tenantValues: tenantValueCounts(p) } : {}),
        ...(Object.hasOwn(p, 'observers') ? { observers: declaredObserverRecord(p.observers) } : {}),
        // Declared app logs (src/app-log-verdicts.mjs): their records, the file path left out.
        ...(Object.hasOwn(p, 'appLogs') ? { appLogs: appLogRecords(p.appLogs) } : {}),
        // Declared channels (src/channels.mjs): a saved run must carry exactly these, so a run stripped of them is refused.
        ...(Object.hasOwn(p, 'channels') ? { channels: structuredClone(p.channels) } : {}),
        // Correlation (run settlement): the header, the recorded (observer, destination) pairs and the settlement mode the runs must carry.
        ...(p.correlation ? { correlation: { header: p.correlation.header, recorded: correlationRecorded(p.observers), mode: p.settlement?.mode ?? 'run' } } : {}),
        // Judged late effects (src/http-settlement.mjs): the declaration the runs' settlement records must carry, only when declared.
        ...(p.settlement?.outsideWindow ? { outsideWindow: p.settlement.outsideWindow } : {}),
        // The effect horizon and run budget (src/http-timing.mjs) the runs must carry.
        ...(p.timing ? { timing: p.timing } : {}),
        // Background attribution (src/http-attribution.mjs): the declared sources the runs must carry, in clear as effects are.
        ...(p.attribution ? { attribution: { background: p.attribution.background } } : {}),
        // The target context (and forwarded target name) the runs must carry.
        targetContext: p.targetContext, targetLabel: p.targetLabel ?? null,
        runnableWith: 'Use the original local profile with ./scopehaven assess --config <file> --target <id>. This redacted summary is not an executable profile.' };
    },
  };
  return registry;
}
