// Open WebUI access-grant importer (layer "openwebui-access-grant").
// Reads an operator export of an Open WebUI instance's declarations (users and roles,
// group memberships, workspace resources with owners, and access_grant rows) and states,
// per user, resource and read/write, what they declare. The rules are the ones in
// Open WebUI 0.11.4 (image sha256:9591b13f...), read from its source:
//   the resource owner                                  -> allow (routes check user_id == user.id)
//   a grant to user:*, to the user, or to one of their groups, same permission -> allow
//                                                          (AccessGrants.has_access; write does not imply read)
//   an admin with no grant                              -> allow when the export says
//                                                          BYPASS_ADMIN_ACCESS_CONTROL is true, else conditional
//                                                          (default true; some routes check role == admin alone)
//   anonymous with an anyone:* grant                    -> conditional (a route must opt in: has_anyone_access)
//   otherwise                                           -> deny (resources are private to the owner by default)
// A resource with only a legacy access_control field is converted the way the 0.11.4
// migration does: null means user:* read (private for files), {} means owner only.
// Roles other than user and admin (pending) are left unknown. Group data that is missing or
// malformed, a grant to a group the export doesn't describe, or a malformed legacy field makes
// the affected resource unknown, never deny.
import { buildMatrix, canonical, sourceRecord } from './matrix.mjs';

export const LAYER = 'openwebui-access-grant';
export const SEMANTICS_VERSION = 'open-webui 0.11.4';
export const EXPORT_SQL = `-- Run on a private copy of webui.db (never the live file). Columns only; no passwords or tokens.
select json_object(
  'openWebUiVersion', '0.11.4',
  'users', (select json_group_array(json_object('id', id, 'role', role)) from user),
  'groups', (select json_group_array(json_object('id', g.id, 'member_ids', (select json_group_array(m.user_id) from group_member m where m.group_id = g.id))) from "group" g),
  'resources', (select json_group_array(json_object('type', type, 'id', id, 'user_id', user_id)) from (
    select 'knowledge' as type, id, user_id from knowledge union all select 'model', id, user_id from model
    union all select 'prompt', id, user_id from prompt union all select 'tool', id, user_id from tool)),
  'grants', (select json_group_array(json_object('resource_type', resource_type, 'resource_id', resource_id, 'principal_type', principal_type, 'principal_id', principal_id, 'permission', permission)) from access_grant));`;
const ACTIONS = ['read', 'write'];
const NOT_EVALUATED = Object.freeze([
  'route-level differences: some routes let admins through without BYPASS_ADMIN_ACCESS_CONTROL, and some treat write as enough to read',
  'workspace feature permissions (group permission flags such as workspace.knowledge) that gate creating or sharing',
  'files attached to a resource, which have their own checks (has_access_to_file)',
]);

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const ids = v => v === undefined ? [] : Array.isArray(v) && v.every(x => typeof x === 'string') ? v : null;

// The 0.11.4 migration's conversion; null when the field isn't a shape it accepts.
function legacyGrants(resource) {
  const ac = resource.access_control, grants = [];
  if (ac === null) return resource.type === 'file' ? [] : [{ principal_type: 'user', principal_id: '*', permission: 'read' }];
  if (!plain(ac)) return null;
  for (const permission of ACTIONS) {
    const data = ac[permission];
    if (data === undefined || data === null) continue;
    if (!plain(data)) return null;
    const groupIds = ids(data.group_ids), userIds = ids(data.user_ids);
    if (!groupIds || !userIds) return null;
    for (const id of groupIds) grants.push({ principal_type: 'group', principal_id: id, permission });
    for (const id of userIds) grants.push({ principal_type: 'user', principal_id: id, permission });
  }
  return grants;
}

// A gap on an export row names the row's index, so its identity (matrix.mjs) takes the reason and scope without the index,
// and the row's content: another row added before it keeps the gap's id.
const row = (kind, value, scope) => ({ kind, subject: canonical(value ?? null), ...(scope ? { scope } : {}) });

export function importOpenWebUi(file, { application } = {}) {
  const text = Buffer.isBuffer(file.content) ? file.content.toString('utf8') : String(file.content);
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`${file.id} is not JSON (see EXPORT_SQL).`); }
  for (const key of ['users', 'resources', 'grants']) if (!Array.isArray(data?.[key])) throw new Error(`${file.id} needs a "${key}" array (see EXPORT_SQL).`);
  const gaps = [], cells = [], assumptions = [`rules read from ${SEMANTICS_VERSION} source`];
  const memberOf = new Map(), knownGroups = new Set();
  if (!Array.isArray(data.groups)) gaps.push({ source: file.id, line: null, scope: 'groups', reason: 'the export has no "groups" array, so group grants cannot be evaluated' });
  else data.groups.forEach((g, index) => {
    const members = g?.member_ids === undefined ? null : ids(g.member_ids);
    if (typeof g?.id !== 'string' || !members) { gaps.push({ source: file.id, line: null, scope: typeof g?.id === 'string' ? `group:${g.id}` : 'groups', reason: `groups[${index}] has no readable id or member_ids`, identity: row('groups[] has no readable id or member_ids', g) }); return; }
    knownGroups.add(g.id);
    for (const uid of members) memberOf.set(uid, new Set([...(memberOf.get(uid) ?? []), g.id]));
  });
  const groupsReadable = Array.isArray(data.groups) && !gaps.some(g => g.scope === 'groups');
  if (data.openWebUiVersion && !/^0\.11\./.test(String(data.openWebUiVersion))) assumptions.push(`the export says Open WebUI ${data.openWebUiVersion}; the rules applied are ${SEMANTICS_VERSION}'s`);
  const bypass = data.bypassAdminAccessControl;
  assumptions.push(bypass === true || bypass === false ? `BYPASS_ADMIN_ACCESS_CONTROL is ${bypass} (from the export)` : 'BYPASS_ADMIN_ACCESS_CONTROL not given (Open WebUI defaults it to true)');
  const grantsFor = new Map();
  data.grants.forEach((g, index) => {
    const ok = g && typeof g.resource_type === 'string' && typeof g.resource_id === 'string' && ['user', 'group', 'anyone'].includes(g.principal_type) && typeof g.principal_id === 'string' && ACTIONS.includes(g.permission);
    if (!ok) { gaps.push({ source: file.id, line: null, scope: g?.resource_type && g?.resource_id ? `${g.resource_type}:${g.resource_id}` : '*', reason: `grants[${index}] is not a readable grant row`, identity: row('grants[] is not a readable grant row', g) }); return; }
    const key = `${g.resource_type}:${g.resource_id}`;
    grantsFor.set(key, [...(grantsFor.get(key) ?? []), { ...g, cite: { source: file.id, line: null, statement: `grants[${index}] ${g.principal_type}:${g.principal_id} ${g.permission}` } }]);
  });
  const roleOf = u => u.alias ?? u.id;
  const seenUsers = new Set();
  const users = data.users.filter((u, index) => {
    if (!u || typeof u.id !== 'string' || typeof u.role !== 'string') { gaps.push({ source: file.id, line: null, scope: `users[${index}]`, reason: `users[${index}] is not a readable user row, so it has no cells`, identity: row('users[] is not a readable user row, so it has no cells', u, 'users[]') }); return false; }
    // Two rows for one user, or a user labelled like the anonymous role, can't be told apart.
    if (seenUsers.has(u.id) || seenUsers.has(roleOf(u)) || roleOf(u) === 'anonymous') { gaps.push({ source: file.id, line: null, scope: '*', reason: `users[${index}] duplicates another user or the anonymous role`, identity: row('users[] duplicates another user or the anonymous role', u) }); return false; }
    seenUsers.add(u.id); seenUsers.add(roleOf(u));
    return true;
  });
  // A resource listed twice is unknown in full, so the duplicate is found before any cells are built.
  const keyOf = r => r && typeof r.type === 'string' && typeof r.id === 'string' ? `${r.type}:${r.id}` : null;
  const counts = new Map(); for (const r of data.resources) { const k = keyOf(r); if (k) counts.set(k, (counts.get(k) ?? 0) + 1); }
  for (const [k, n] of counts) if (n > 1) gaps.push({ source: file.id, line: null, scope: k, reason: `${k} is listed ${n} times` });
  const globalGap = gaps.some(g => g.scope === '*');
  const seenResources = new Set();
  data.resources.forEach((r, index) => {
    if (!r || typeof r.type !== 'string' || typeof r.id !== 'string' || typeof r.user_id !== 'string') { gaps.push({ source: file.id, line: null, scope: `resources[${index}]`, reason: `resources[${index}] is not a readable resource row, so it has no cells`, identity: row('resources[] is not a readable resource row, so it has no cells', r, 'resources[]') }); return; }
    if (seenResources.has(`${r.type}:${r.id}`)) return;
    seenResources.add(`${r.type}:${r.id}`);
    const key = `${r.type}:${r.id}`, rowCite = { source: file.id, line: null, statement: `resources[${index}] ${key} owner ${r.user_id}` };
    let grants = grantsFor.get(key) ?? [];
    if (!grants.length && Object.hasOwn(r, 'access_control')) {
      const legacy = legacyGrants(r);
      if (!legacy) gaps.push({ source: file.id, line: null, scope: key, reason: `resources[${index}] has a legacy access_control the 0.11.4 migration would not accept`, identity: row('resources[] has a legacy access_control the 0.11.4 migration would not accept', r) });
      grants = (legacy ?? []).map(g => ({ ...g, cite: { ...rowCite, statement: `${rowCite.statement} legacy access_control ${JSON.stringify(r.access_control)}` } }));
      if (legacy) assumptions.push(`${key}: legacy access_control converted as the 0.11.4 migration does`);
    }
    for (const g of grants) if (g.principal_type === 'group' && (!groupsReadable || !knownGroups.has(g.principal_id)))
      gaps.push({ source: file.id, line: null, scope: key, reason: `${key} grants group ${g.principal_id}, whose membership the export doesn't describe` });
    const tableGap = globalGap || gaps.some(g => g.scope === key);
    for (const action of ACTIONS) {
      for (const u of users) {
        const base = { role: roleOf(u), resource: key, action }, groupIds = memberOf.get(u.id) ?? new Set();
        const match = grants.filter(g => g.permission === action && ((g.principal_type === 'user' && (g.principal_id === '*' || g.principal_id === u.id)) || (g.principal_type === 'group' && groupIds.has(g.principal_id))));
        let cell;
        if (!['user', 'admin'].includes(u.role)) cell = { ...base, decision: 'unknown', basis: `role ${u.role} not evaluated (only verified user and admin roles reach these routes)`, citations: [rowCite] };
        else if (r.user_id === u.id) cell = { ...base, decision: 'allow', basis: 'owner', citations: [rowCite] };
        else if (match.length) cell = { ...base, decision: 'allow', basis: `grant ${match[0].principal_type}:${match[0].principal_id}`, citations: match.map(g => g.cite) };
        else if (u.role === 'admin') cell = bypass === true ? { ...base, decision: 'allow', basis: 'admin-bypass (BYPASS_ADMIN_ACCESS_CONTROL=true)', citations: [rowCite] }
          : { ...base, decision: 'conditional', basis: 'admin-bypass-setting', conditions: [`admin bypass: BYPASS_ADMIN_ACCESS_CONTROL ${bypass === false ? 'is false, but some routes check role == admin alone' : 'not given (default true)'}`], citations: [rowCite] };
        else cell = { ...base, decision: 'deny', basis: 'no-grant (private to the owner by default)', citations: [rowCite] };
        if (tableGap) cell = { ...cell, computedDecision: cell.decision, decision: 'unknown', basis: 'source-gap', unknownReasons: [...(cell.decision === 'unknown' ? [cell.basis] : []), 'source-gap'] };
        cells.push(cell);
      }
      const anyone = grants.filter(g => g.principal_type === 'anyone' && g.principal_id === '*' && g.permission === action);
      let anon = anyone.length ? { role: 'anonymous', resource: key, action, decision: 'conditional', basis: 'anyone-grant', conditions: ['the route must opt in to no-auth access (has_anyone_access)'], citations: anyone.map(g => g.cite) }
        : { role: 'anonymous', resource: key, action, decision: 'deny', basis: 'no-anyone-grant', citations: [rowCite] };
      if (tableGap) anon = { ...anon, computedDecision: anon.decision, decision: 'unknown', basis: 'source-gap', unknownReasons: ['source-gap'] };
      cells.push(anon);
    }
  });
  const listed = new Set(data.resources.filter(r => r && typeof r.type === 'string' && typeof r.id === 'string').map(r => `${r.type}:${r.id}`));
  const orphans = [...grantsFor.keys()].filter(key => !listed.has(key)).sort();
  const notEvaluated = [...NOT_EVALUATED];
  if (orphans.length) notEvaluated.push(`${orphans.length} granted ${orphans.length === 1 ? 'resource is' : 'resources are'} not in the export's resource rows (for example base models), so ${orphans.length === 1 ? 'it has' : 'they have'} no cells: ${orphans.join(', ')}`);
  return buildMatrix({ application, layer: LAYER, sources: [sourceRecord({ id: file.id, kind: 'openwebui-export-json', content: text })], cells, gaps, notEvaluated, assumptions });
}
