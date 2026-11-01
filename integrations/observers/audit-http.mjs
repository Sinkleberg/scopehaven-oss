// HTTP audit-log observer: reads an application's own audit endpoint (for
// example an admin "activity" API) through the connector's loopback-only HTTP
// client. Entries need a numeric id; a window is the rows present at its end
// mark and absent at its start mark.
// Only the declared fields are read; entry content is reduced to a digest.
import { observeHttp } from '../../src/http-connector.mjs';
import { createHmac, randomBytes } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { makeEffect, credentialFrom, OPERATIONS } from './events.mjs';

const pointer = (root, path) => {
  let value = root;
  for (const token of path === '' ? [] : path.slice(1).split('/').map(t => t.replaceAll('~1', '/').replaceAll('~0', '~'))) {
    if (['__proto__', 'prototype', 'constructor'].includes(token) || value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return undefined;
    value = value[token];
  }
  return value;
};

// config: { origin, path, credentialEnv?, credentialCookie?, itemsPointer, fields: { id, actor, action, resource? },
//           actions: { <action>: operation }, deniedActions?: [], principals?: [], maxResponseBytes?, pageLimit }
// pageLimit (required): the endpoint's page size. A response that long may omit the newest rows, so the mark fails.
export function createHttpAuditObserver({ instanceId = 'http-audit-1', env = process.env, transport = observeHttp, ...config }) {
  const observer = { kind: 'http-audit-endpoint', instanceId };
  // An actor that is not a declared principal, and the entry it came from, are kept only as digests keyed with a secret
  // this observer never stores: an unkeyed hash of a guessable value (an email, a user id) is confirmed by hashing guesses.
  const key = randomBytes(32), keyed = value => createHmac('sha256', key).update(digest(value)).digest('hex');
  const principals = config.principals || [];
  const credential = config.credentialEnv === undefined ? undefined : credentialFrom(env, config.credentialEnv, 'Audit observer');
  if (config.credentialEnv !== undefined && !credential) throw new Error('The audit observer credential reference is not set.');
  // The page size is required: without it, an endpoint that returns its oldest
  // rows first would look complete while hiding the newest entries.
  if (!Number.isSafeInteger(config.pageLimit) || config.pageLimit < 2) throw new Error('Declare the audit endpoint\'s page size ("pageLimit", 2 or more).');
  const mapped = Object.values(config.actions || {});
  if (!mapped.every(op => OPERATIONS.includes(op))) throw new Error('Audit actions must map to supported operations.');
  const read = async () => {
    const observation = await transport(config.origin, { method: 'GET', path: config.path }, { credential, credentialCookie: config.credentialCookie, timeoutMs: 5000, maxResponseBytes: config.maxResponseBytes ?? 1024 * 1024 });
    if (observation.status !== 200 || !observation.jsonParsed) throw new Error('audit-read-failed');
    const items = pointer(observation.json, config.itemsPointer ?? '');
    if (!Array.isArray(items)) throw new Error('audit-shape');
    // A response as long as the declared page limit may be missing the newest rows.
    if (items.length >= config.pageLimit) throw new Error('audit-page-full');
    // Keep only what the evaluator needs: id, actor, action, resource and a digest of the entry.
    return items.filter(item => Number.isSafeInteger(Number(pointer(item, config.fields.id)))).map(item => ({ id: Number(pointer(item, config.fields.id)),
      actor: pointer(item, config.fields.actor), action: pointer(item, config.fields.action), resource: config.fields.resource ? pointer(item, config.fields.resource) : undefined, digest: keyed(item) }));
  };
  // Each mark keeps the set of ids it saw. A window is the rows present at its
  // end mark and absent at its start mark, so a row with a lower id that became
  // visible late is still in the window.
  const snapshot = async () => { const rows = await read(); return { ok: true, rows: new Map(rows.map(r => [r.id, r])), max: rows.reduce((m, r) => Math.max(m, r.id), 0) }; };
  return {
    kind: observer.kind, instanceId, source: 'http-audit-log',
    // The declared actions are its name vocabulary: it vouches only for actions it logs.
    scope: Object.freeze({ operations: [...new Set([...mapped, 'update'])], names: [...new Set([...Object.keys(config.actions || {}), ...(config.deniedActions || [])])], actorAttribution: 'principal', evidence: 'authoritative' }),
    async start() { await read(); },
    async mark() { try { return await snapshot(); } catch (error) { return { ok: false, reason: error.message }; } },
    async collect(from, to) {
      if (!from.ok || !to.ok) return { events: [], coverage: 'failed', reason: (from.ok ? to : from).reason };
      if (to.max < from.max) return { events: [], coverage: 'failed', reason: 'audit-id-went-backward' };
      const added = [...to.rows.values()].filter(r => !from.rows.has(r.id)).sort((a, b) => a.id - b.id);
      // Rows the endpoint stopped returning, or ids missing in the new range, mean entries may be hidden.
      const vanished = [...from.rows.keys()].some(id => !to.rows.has(id));
      let missingInRange = false;
      for (let id = from.max + 1; id <= to.max && !missingInRange; id++) if (!to.rows.has(id)) missingInRange = true;
      const events = added.map(r => {
        const action = String(r.action ?? 'unknown').slice(0, 128);
        return makeEffect({ source: 'http-audit-log', observer, seq: r.id, actor: r.actor === undefined || r.actor === null ? null : principals.includes(String(r.actor)) ? String(r.actor) : `unlisted:${keyed(String(r.actor)).slice(0, 16)}`,
          operation: config.actions?.[action] ?? 'update', name: action, resource: r.resource === undefined || r.resource === null ? null : String(r.resource).slice(0, 200),
          outcome: (config.deniedActions || []).includes(action) ? 'denied' : 'committed', content: r.digest });
      });
      const reason = vanished ? 'audit-rows-vanished' : missingInRange ? 'audit-ids-not-contiguous' : null;
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    async stop() {},
  };
}
