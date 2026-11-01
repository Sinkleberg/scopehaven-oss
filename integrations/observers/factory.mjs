// Builds observers from declared configurations (an HTTP profile's
// "observers", or a sequence CLI's observers.json). Each field is passed
// explicitly: a configuration can never supply its own environment,
// transport or instance identity, and credentials come only from this
// process's SCOPEHAVEN_TARGET_ variables (checked by each observer). The
// instance id is derived: "<type>-<id>", from a validated id that is unique
// in the configuration (the entry's position when no id is given).
// lockFallback (which opens the application's live rollback-journal database
// under a shared lock) is never taken from a configuration: operator code only.
import { createOtelObserver } from './otel.mjs';
import { createSqliteAuditObserver, createSqliteSnapshotObserver } from './sqlite.mjs';
import { createHttpAuditObserver } from './audit-http.mjs';
import { createMcpObserver } from './mcp.mjs';
import { createAuditFileObserver, AUDIT_FILE_LIMITS } from './audit-file.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createPgWalObserver } from './pg-wal.mjs';
import { supabaseResolver } from './supabase-rules.mjs';
import { createEgressRecorder } from './egress-recorder.mjs';
import { crossDestinationsOf } from '../../src/egress-rules.mjs';
import { createSmtpSink } from './smtp-sink.mjs';
import { createMysqlSnapshotObserver } from './mysql-snapshot.mjs';
import { createProviderFeedObserver } from './provider-feed.mjs';

import { OBSERVER_TYPES, OBSERVER_ID, observerInstanceId, settleDeclared } from '../../src/http-effects.mjs';
export { OBSERVER_TYPES };
// watchedResources: the resources the profile's effect selectors name (from the connector), for snapshot observers.
// supabaseRules: the target's Supabase identity rules (./supabase-rules.mjs, NC9 item 3), whose resolver each observer with actor
// capture joins with; validated with the profile (src/contracts.mjs).
// actorCapture: true when the caller's run validators read a Postgres observer's actor capture (the HTTP connector); any other
// caller (sequences) is refused a configuration that declares one (PR518 review MINOR 2).
// pgWal: true when the caller pairs and validates pg-wal windows (the HTTP connector); sequences, which have no pairing stage and whose
// validators do not know its kind, are refused one (PR521 review MINOR 2).
export function buildObservers(configs, { env = process.env, watchedResources = [], supabaseRules, actorCapture: capturesRead = false, pgWal = false } = {}) {
  if (!Array.isArray(configs) || configs.length > 16) throw new Error('Declare at most 16 observers.');
  const ids = configs.map((c, i) => c !== null && typeof c === 'object' && Object.hasOwn(c, 'id') ? c.id : String(i + 1));
  ids.forEach((id, i) => { if (typeof id !== 'string' || !OBSERVER_ID.test(id) || ids.indexOf(id) !== i) throw new Error(`Observer entry ${i + 1} needs a unique "id" of 1-48 letters, digits, "_" or "-".`); });
  if (configs.some(c => c !== null && typeof c === 'object' && Object.hasOwn(c, 'lockFallback'))) throw new Error('lockFallback cannot be set from a configuration.');
  return configs.map((c, i) => {
    if (!OBSERVER_TYPES.includes(c?.type)) throw new Error(`Unsupported observer type in entry ${i + 1}.`);
    // The declared post-response settle, for callers that place their own end marks (sequences).
    // An otel observer uses settleMs as its own quiescence wait instead.
    return Object.assign(build(c, observerInstanceId(c.type, ids[i]), i), { postResponseSettleMs: c.type !== 'otel' && settleDeclared(c.settleMs) ? c.settleMs : null });
  });
  // The background-writer options (N12) a Postgres observer declares, each only when declared (runKey stays a test seam).
  function backgroundOf(c) { return Object.fromEntries(['platform', 'ignore', 'queues', 'drainTimeoutMs', 'pollMs', 'runLease'].filter(key => c[key] !== undefined).map(key => [key, c[key]])); }
  function actorCaptureOf(c, i) {
    if (c.actorCapture === undefined) return {};
    if (!capturesRead) throw new Error(`Observer entry ${i + 1}: actorCapture is read only by an HTTP assessment's observers.`);
    if (c.actorCapture === null || typeof c.actorCapture !== 'object' || Array.isArray(c.actorCapture)) throw new Error(`Observer entry ${i + 1}: actorCapture is { block, installedSha256 }.`);
    return { actorCapture: { block: c.actorCapture.block, installedSha256: c.actorCapture.installedSha256, ...(supabaseRules === undefined ? {} : { resolve: supabaseResolver(supabaseRules) }) } };
  }
  function build(c, instanceId, i) {
    if (c.type === 'otel') return createOtelObserver({ instanceId, port: c.port ?? 4318, services: c.services, tools: c.tools ?? null, principals: c.principals ?? [], settleMs: c.settleMs });
    if (c.type === 'sqlite-audit') return createSqliteAuditObserver({ instanceId, path: c.path, audit: c.audit, principals: c.principals });
    if (c.type === 'sqlite-snapshot') return createSqliteSnapshotObserver({ instanceId, path: c.path, tables: c.tables, changeColumnSkewMs: c.changeColumnSkewMs, maxCommitLagMs: c.maxCommitLagMs, watchedResources });
    if (c.type === 'http-audit') return createHttpAuditObserver({ instanceId, env, origin: c.origin, path: c.path, credentialEnv: c.credentialEnv, credentialCookie: c.credentialCookie, itemsPointer: c.itemsPointer, fields: c.fields, actions: c.actions, deniedActions: c.deniedActions, principals: c.principals, maxResponseBytes: c.maxResponseBytes, pageLimit: c.pageLimit });
    // Without a path the MCP observer would read an in-process proxy log, which a configuration cannot supply.
    if (c.type === 'mcp-log') {
      if (typeof c.path !== 'string' || !c.path) throw new Error(`Observer entry ${i + 1} (mcp-log) needs "path": the recorder's log file.`);
      return createMcpObserver({ instanceId, path: c.path, deniedRpcCodes: c.deniedRpcCodes, tools: c.tools ?? null });
    }
    // actorCapture (./pg-actor.mjs, NC2 item 2): the installed capture's block and its installation digest, joined with the target's
    // Supabase rules' resolver when it declares supabaseRules (NC9 item 3); without actorCapture the observer is exactly as before.
    if (c.type === 'pg-snapshot') return createPgSnapshotObserver({ instanceId, env, host: c.host, port: c.port, database: c.database, credentialEnv: c.credentialEnv, tables: c.tables, watchedResources, ...(c.rowsPerTable === undefined ? {} : { rowsPerTable: c.rowsPerTable }), ...(c.statementTimeoutMs === undefined ? {} : { statementTimeoutMs: c.statementTimeoutMs }),
      ...backgroundOf(c), ...actorCaptureOf(c, i) });
    // The Postgres WAL observer (NC9 item 4; ./pg-wal.mjs, docs/PG-WAL.md): its declared tables, value columns and barrier, the
    // background-writer options and the actor capture, as declared (its own defaults otherwise: runLease on).
    if (c.type === 'pg-wal' && !pgWal) throw new Error(`Observer entry ${i + 1}: pg-wal is built only for an HTTP assessment's observers.`);
    if (c.type === 'pg-wal') return createPgWalObserver({ instanceId, env, host: c.host, port: c.port, database: c.database, credentialEnv: c.credentialEnv, tables: c.tables,
      ...(c.statementTimeoutMs === undefined ? {} : { statementTimeoutMs: c.statementTimeoutMs }), ...(c.barrierMs === undefined ? {} : { barrierMs: c.barrierMs }), ...backgroundOf(c), ...actorCaptureOf(c, i) });
    if (c.type === 'egress-recorder') return createEgressRecorder({ instanceId, env, port: c.port, routing: c.routing, destinations: c.destinations, routes: c.routes, witness: c.witness,
      witnessWaitMs: c.witnessWaitMs, quietMs: c.quietMs, maxBodyBytes: c.maxBodyBytes, reply: c.reply, replies: c.replies, signingClock: () => Date.now(), wallClock: () => Date.now(), ...(c.requestFeed === undefined ? {} : { requestFeed: c.requestFeed }),
      // FIX-08 (egress-recorder/13): the destinations the profile's other egress recorders declare that this one does not.
      ...(crossDestinationsOf(c, configs) ? { crossDestinations: crossDestinationsOf(c, configs) } : {}) });
    if (c.type === 'mysql-snapshot') return createMysqlSnapshotObserver({ instanceId, env, host: c.host, port: c.port, database: c.database, credentialEnv: c.credentialEnv, tables: c.tables, watchedResources, maxCommitLagMs: c.maxCommitLagMs,
      ...(c.rowsPerTable === undefined ? {} : { rowsPerTable: c.rowsPerTable }), ...(c.statementTimeoutMs === undefined ? {} : { statementTimeoutMs: c.statementTimeoutMs }), ...(c.tableIds === undefined ? {} : { tableIds: c.tableIds }) });
    if (c.type === 'smtp-sink') return createSmtpSink({ instanceId, port: c.port, routing: c.routing, domains: c.domains, witness: c.witness, witnessWaitMs: c.witnessWaitMs, quietMs: c.quietMs, maxMessageBytes: c.maxMessageBytes });
    if (c.type === 'provider-feed') return createProviderFeedObserver({ instanceId, feedId: c.feedId, feed: c.feed, publicKey: c.publicKey, domains: c.domains, routing: c.routing, witness: c.witness,
      witnessWaitMs: c.witnessWaitMs, quietMs: c.quietMs, pollMs: c.pollMs, maxSkewMs: c.maxSkewMs, ...(c.templates === undefined ? {} : { templates: c.templates }), ...(c.outcomes === undefined ? {} : { outcomes: c.outcomes }),
      // The declared key source (FIX-06, provider-feed/7): the observer's windows name it in scope.feed, as the run record does.
      ...(c.keySource === undefined ? {} : { keySource: c.keySource }), ...(c.adapterReads === undefined ? {} : { adapterReads: c.adapterReads }) });
    if (c.type === 'audit-file') {
      // witnessWaitMs: how long collect() waits for the witness line; quietMs: the quiet period after it.
      const o = createAuditFileObserver({ instanceId, path: c.path, origin: c.origin, rules: c.rules, ignore: c.ignore, actors: c.logActors, fields: c.fields,
        witness: c.witness?.rule, settleMs: c.witnessWaitMs ?? AUDIT_FILE_LIMITS.settleMs, quietMs: c.quietMs ?? AUDIT_FILE_LIMITS.quietMs });
      const w = c.witness;
      if (!w || w.method !== 'GET' || !o.witnessRouteMatches('GET', w.path)) throw new Error(`Observer entry ${i + 1}: the witness request must be logged as its witness rule (method and path).`);
      return Object.assign(o, { witnessRequest: Object.freeze({ actorId: w.actorId, method: 'GET', path: w.path }), quietMs: c.quietMs ?? AUDIT_FILE_LIMITS.quietMs });
    }
    throw new Error(`Unsupported observer type in entry ${i + 1}.`);
  }
}
