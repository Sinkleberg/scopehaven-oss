// OpenAPI 3.x security importer (layer "openapi-security").
// Reads an OpenAPI 3.0 or 3.1 document (JSON; convert YAML first) and states, per role,
// path template and method, what its security requirements declare:
//   no security at the operation or document level -> undeclared
//   security: [] or an empty requirement {}          -> allow for everyone, including anonymous
//   the role holds every scheme and scope of at least one requirement -> allow
//   otherwise                                         -> deny (the document declares the requirement)
// Roles come from an operator role map ({ role: { schemeName: [scopes] } }); without one,
// each distinct requirement becomes its own role, plus "anonymous". A reference to an
// undefined scheme or an unresolved path item $ref makes that operation unknown.
// OpenAPI declares who may call an operation, not which records a caller may touch, so
// object-level authorization is listed as not evaluated on every matrix. The document's
// server path prefixes go in context.serverBases so a drafter requests the real route;
// operations with their own servers are listed in context.ownServers and never prefixed.
import { buildMatrix, canonical, sourceRecord } from './matrix.mjs';

export const LAYER = 'openapi-security';
const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
const NOT_EVALUATED = Object.freeze([
  'object-level (per-record) authorization: OpenAPI declares who may call an operation, not which records',
  'whether the running service enforces the declared requirements (that is what the drafted checks test)',
  'scheme semantics beyond names and scopes (token audience, expiry, issuer)',
]);
// Derived role names carry a prefix, so a scheme called "anonymous" never stands for the anonymous caller.
const label = requirement => `requirement:${Object.keys(requirement).sort().map(s => Array.isArray(requirement[s]) && requirement[s].length ? `${s}[${[...requirement[s]].sort().join(' ')}]` : s).join('+') || 'none'}`;
const serverBase = server => {
  if (typeof server?.url !== 'string' || server.url.includes('{')) return null;
  // A relative URL without a leading slash resolves against the document's own location, which is unknown here.
  if (!/^(?:https?:\/\/|\/)/i.test(server.url)) return null;
  try { return new URL(server.url, 'http://server.invalid').pathname.replace(/\/+$/, ''); } catch { return null; }
};
const pointer = parts => `#/${parts.map(p => String(p).replaceAll('~', '~0').replaceAll('/', '~1')).join('/')}`;

export function importOpenApi(file, { application, roleMap } = {}) {
  const text = Buffer.isBuffer(file.content) ? file.content.toString('utf8') : String(file.content);
  let doc;
  try { doc = JSON.parse(text); } catch { throw new Error(`${file.id} is not JSON. Convert a YAML document to JSON first.`); }
  if (typeof doc?.openapi !== 'string' || !/^3\.[01]\./.test(doc.openapi)) throw new Error(`${file.id} is not an OpenAPI 3.0 or 3.1 document.`);
  const schemes = doc.components?.securitySchemes ?? {};
  const gaps = [], operations = [], ownServers = [];
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    if (item && typeof item.$ref === 'string') { gaps.push({ source: file.id, line: null, scope: path, reason: `path item ${path} is a $ref, which is not resolved`, identity: { subject: canonical(item) } }); operations.push({ path, method: '*', unresolved: true }); continue; }
    for (const method of METHODS) {
      const op = item?.[method];
      if (!op) continue;
      if (Object.hasOwn(item, 'servers') || Object.hasOwn(op, 'servers')) ownServers.push(`${method.toUpperCase()} ${path}`);
      const own = Object.hasOwn(op, 'security'), security = own ? op.security : doc.security;
      const at = own ? pointer(['paths', path, method, 'security']) : Object.hasOwn(doc, 'security') ? '#/security' : null;
      operations.push({ path, method: method.toUpperCase(), security, at, operationId: op.operationId });
    }
  }
  const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (roleMap !== undefined && (!plain(roleMap) || Object.values(roleMap).some(held => !plain(held) || Object.values(held).some(scopes => !Array.isArray(scopes) || scopes.some(x => typeof x !== 'string')))))
    throw new Error('roleMap must map role names to { scheme: [scope strings] }.');
  let roles;
  if (roleMap) roles = Object.entries(roleMap).map(([name, held]) => ({ name, held }));
  else {
    const seen = new Map([['anonymous', {}]]);
    for (const op of operations) for (const requirement of Array.isArray(op.security) ? op.security : []) if (requirement && typeof requirement === 'object' && !Array.isArray(requirement) && Object.values(requirement).every(Array.isArray) && Object.keys(requirement).length) seen.set(label(requirement), requirement);
    roles = [...seen].map(([name, held]) => ({ name, held }));
  }
  if (!roles.some(r => r.name === 'anonymous')) roles.push({ name: 'anonymous', held: {} });
  const holds = (held, requirement) => Object.entries(requirement).every(([scheme, scopes]) => Array.isArray(held[scheme]) && (scopes ?? []).every(s => held[scheme].includes(s)));
  const cells = [];
  for (const op of operations) {
    if (op.unresolved) { for (const r of roles) cells.push({ role: r.name, resource: op.path, action: '*', decision: 'unknown', basis: 'unresolved-path-item-ref', citations: [{ source: file.id, line: null, statement: pointer(['paths', op.path, '$ref']) }] }); continue; }
    const cite = op.at ? [{ source: file.id, line: null, statement: `${op.at}${op.operationId ? ` (${op.operationId})` : ''}` }] : [];
    const invalid = op.security !== undefined && (!Array.isArray(op.security) || op.security.some(r => !r || typeof r !== 'object' || Array.isArray(r) || Object.values(r).some(v => !Array.isArray(v))));
    const missing = !invalid && Array.isArray(op.security) ? op.security.flatMap(r => Object.keys(r)).filter(s => !Object.hasOwn(schemes, s)) : [];
    if (invalid || missing.length) gaps.push({ source: file.id, line: null, scope: `${op.method} ${op.path}`, reason: invalid ? 'security is not a list of requirement objects' : `undefined security scheme${new Set(missing).size === 1 ? '' : 's'}: ${[...new Set(missing)].join(', ')}`,
      identity: { subject: canonical(op.security ?? null) } });
    for (const r of roles) {
      const base = { role: r.name, resource: op.path, action: op.method };
      if (invalid || missing.length) cells.push({ ...base, decision: 'unknown', basis: invalid ? 'invalid-security' : 'undefined-security-scheme', citations: cite });
      else if (op.security === undefined) cells.push({ ...base, decision: 'undeclared', basis: 'no-security-declared', citations: [] });
      else if (!op.security.length) cells.push({ ...base, decision: 'allow', basis: 'security-empty-public', citations: cite });
      else if (op.security.some(req => holds(r.held, req))) cells.push({ ...base, decision: 'allow', basis: op.security.some(req => !Object.keys(req).length) ? 'optional-authentication' : 'requirement-met', citations: cite });
      else cells.push({ ...base, decision: 'deny', basis: 'requirement-not-met', citations: cite });
    }
  }
  const assumptions = [roleMap ? 'roles hold exactly the schemes and scopes in the operator role map' : 'no role map: each distinct security requirement is its own role'];
  const declared = Array.isArray(doc.servers) && doc.servers.length ? doc.servers : [{ url: '/' }];
  const bases = declared.map(serverBase);
  const context = { serverBases: bases.includes(null) ? null : [...new Set(bases)], ownServers };
  return buildMatrix({ application, layer: LAYER, sources: [sourceRecord({ id: file.id, kind: 'openapi-json', content: text })], cells, gaps, notEvaluated: [...NOT_EVALUATED], assumptions, context });
}
