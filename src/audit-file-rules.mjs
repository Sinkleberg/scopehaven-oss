// Audit-log file observer configuration (integrations/observers/audit-file.mjs),
// validated when an HTTP profile is validated, before any request. Pure: no I/O.
import { OPERATIONS } from './effect-events.mjs';

export const AUDIT_FILE_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
export const AUDIT_FILE_BOUNDS = Object.freeze({ rules: 64, ignore: 256, quietMs: [100, 10000], witnessWaitMs: [0, 30000] });
// "/api/v1/knowledge/{id}/update": {x} matches exactly one path segment.
export function compileAuditPath(template) {
  if (typeof template !== 'string' || !template.startsWith('/') || template.length > 300 || /\/\/|;/.test(template)) throw new Error('Paths must be templates starting with "/".');
  const parts = template.split('/').map(part => /^\{[A-Za-z0-9_]{1,40}\}$/.test(part) ? '[^/]+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(`^${parts.join('/')}/?$`, 'i');
}
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const intIn = (value, [min, max]) => Number.isInteger(value) && value >= min && value <= max;
const WITNESS_KEYS = ['rule', 'actorId', 'method', 'path'];

// Throws an Error with a short reason; returns the compiled rules.
export function validateAuditFileConfig(o, actors) {
  if (typeof o.path !== 'string' || !o.path) throw new Error('declare the audit log file "path"');
  let origin;
  try { origin = new URL(o.origin); } catch { throw new Error('declare the application "origin" as it appears in the log'); }
  if (!['http:', 'https:'].includes(origin.protocol) || origin.pathname !== '/' || origin.search || origin.hash || origin.username || origin.password) throw new Error('"origin" must be scheme://host:port only');
  if (!Array.isArray(o.rules) || !o.rules.length || o.rules.length > AUDIT_FILE_BOUNDS.rules) throw new Error('declare 1 to 64 audit "rules"');
  const rules = o.rules.map(rule => {
    if (!object(rule) || !/^[A-Za-z0-9_.:-]{1,128}$/.test(rule.name || '') || !AUDIT_FILE_METHODS.includes(rule.method)) throw new Error('each audit rule needs a name and an HTTP method');
    if (rule.operation !== undefined && !OPERATIONS.includes(rule.operation)) throw new Error('audit rule operations must be supported operations');
    if (rule.refusedStatuses !== undefined && !(Array.isArray(rule.refusedStatuses) && rule.refusedStatuses.every(s => Number.isInteger(s) && s >= 400 && s <= 499))) throw new Error('"refusedStatuses" may only list 4xx statuses');
    return { name: rule.name, method: rule.method, regex: compileAuditPath(rule.path) };
  });
  if (new Set(rules.map(r => r.name)).size !== rules.length) throw new Error('audit rule names must be unique');
  if (o.ignore !== undefined && !(Array.isArray(o.ignore) && o.ignore.length <= AUDIT_FILE_BOUNDS.ignore && o.ignore.every(i => object(i) && (i.method === undefined || AUDIT_FILE_METHODS.includes(i.method)) && compileAuditPath(i.path)))) throw new Error('"ignore" lists { method?, path } templates');
  if (o.logActors !== undefined && !(object(o.logActors) && Object.values(o.logActors).every(v => typeof v === 'string' || Number.isInteger(v)))) throw new Error('"logActors" maps principals to the log\'s actor values');
  if (o.fields !== undefined && !(object(o.fields) && Object.values(o.fields).every(v => typeof v === 'string' && (v === '' || v.startsWith('/'))))) throw new Error('"fields" maps names to JSON pointers');
  if (o.quietMs !== undefined && !intIn(o.quietMs, AUDIT_FILE_BOUNDS.quietMs)) throw new Error('"quietMs" must be an integer from 100 to 10000');
  if (o.witnessWaitMs !== undefined && !intIn(o.witnessWaitMs, AUDIT_FILE_BOUNDS.witnessWaitMs)) throw new Error('"witnessWaitMs" must be an integer from 0 to 30000');
  // The witness: a GET the app logs as exactly one rule, the witness rule. A POST
  // would change the app's state on every check, so it is not accepted.
  const w = o.witness;
  if (!object(w) || Object.keys(w).some(key => !WITNESS_KEYS.includes(key))) throw new Error('"witness" is { rule, actorId, method: "GET", path } and nothing else');
  if (w.method !== 'GET') throw new Error('the witness must be a GET the app logs (a POST would change the app\'s state on every check)');
  // A string first: Object.hasOwn coerces its key, so ["member"] would pass here while the connector's credential filter and the
  // lifecycle witness rule, which compare strictly, never match it (D-01's shape, #502).
  if (!object(actors) || typeof w.actorId !== 'string' || !Object.hasOwn(actors, w.actorId)) throw new Error('the witness "actorId" must be a declared actor');
  if (typeof w.path !== 'string' || !w.path.startsWith('/') || w.path.startsWith('//') || w.path.length > 300 || /[#\s]/.test(w.path)) throw new Error('the witness "path" must be an origin-form path without a fragment');
  let decoded;
  try { decoded = decodeURIComponent(w.path); } catch { throw new Error('the witness "path" must be validly percent-encoded'); }
  if (/scopehaven_witness/i.test(decoded)) throw new Error('the witness "path" cannot carry its own witness parameter');
  const route = w.path.split('?')[0], matched = rules.filter(r => r.method === 'GET' && r.regex.test(route));
  if (matched.length !== 1 || matched[0].name !== w.rule) throw new Error('the witness request must match exactly one rule: its witness rule');
  return rules;
}
