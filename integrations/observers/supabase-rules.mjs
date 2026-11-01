// Supabase identity rules (NC2 item 3), over the actor capture's ledger (./pg-actor.mjs). Pure: no I/O.
//
// Three behaviours make a naive check wrong on Supabase, the common buyer stack:
//   - Server-side tools often write with the service role, which bypasses row-level security and carries no user: the
//     request.jwt.claims PostgREST sets for it hold role "service_role" and no "sub". Read as the end user, such a write
//     would credit or blame the user for what the tool did. A direct connection as postgres (an ORM, a migration, an
//     admin tool) bypasses row-level security too.
//   - An UPDATE or DELETE that row-level security filters returns zero rows and no error (PostgREST answers 200 with an
//     empty list, or 204). An application that does not check the count reports success for a write that never happened.
//   - The acting user is the per-transaction request.jwt.claims setting, not a database role (every signed-in user is
//     "authenticated"). ./pg-actor.mjs records it per write and reads it only as PostgREST binds it.
//
// (a) supabaseResolver(decl): the resolver the capture's joins use (pg-actor attributeChange and attributeNetChange
//     { resolve }). A write whose claims role, or effective role (SET ROLE, else the login role), is a declared service
//     role (by default service_role, postgres and supabase_admin, the roles that bypass row-level security on a Supabase
//     stack) is the declared tool's, never the end user's: its event actor is unlisted:tool:<tool>, which no actor-pinned
//     clause reads as a declared principal, so a clause pinned to the end user reads missing (inconclusive) and
//     serviceRoleNotes names the reason, service-role-write. Unless the application passes the user through, as declared:
//     "passThrough" { from: "jwt-claims" } (a service JWT the application minted with the user's "sub") or { from: "column" }
//     (the row's declared actorColumn, which the capture records only when the statement wrote it, and never on a DELETE),
//     mapped through the capture's principals. A pass-through value that is not a declared principal is still the tool's.
//     Every other write resolves as the capture declares (pg-actor resolveActor).
// (b) rlsZeroRow({ check, row, entries, ... }): an UPDATE or DELETE recorded as a zero-row statement in a check's window
//     (the agent's request expected to change rows and changed none) is reported as rls-zero-row. FAIL-only, and FAIL only
//     where the profile declares the action should have succeeded for an allowed user: the check is an allowed-use control
//     (the allowed-use twin) that declares its expected write ("allowedWrites": { "<control id>": { table, op } }), its
//     response contract was decided as success (every response assertion passed on a complete response), and the window
//     holds a zero-row statement on that table and operation by that control's own actor (never the tool's), at any depth (a
//     view's INSTEAD OF trigger or an apply trigger is the declared write's path), with no row that operation changed on that
//     table in the window by that actor or the tool (another principal's write is named on the finding, alsoWrittenBy), and
//     no row changed on that table in the same transaction (so an upsert that inserted, whose
//     ON CONFLICT UPDATE changed nothing, and a MERGE's untaken actions are not refusals). Every other zero-row statement is informational: a boundary check's refusal working, another actor's
//     or the tool's statement, a refusal the application surfaced, a write the control did not declare (a foreign-key
//     cascade lands on another table, and PostgreSQL 17 records it at depth 1). The rule never passes: no zero-row
//     statement says nothing. A window whose capture did not verify intact, or whose ledger read failed, is inconclusive.
//
// Limits. The FAIL is suppressed whenever the control's own actor or the tool changed a row of the declared table by that
// operation in the window, or any statement changed a row of that table in the same transaction, even another row or a
// trigger's history row: the rule errs toward informational, never toward a FAIL. A zero-row statement is not proof that
// row-level security filtered it: a WHERE that matches nothing (a wrong id) is recorded the same way, so the FAIL rests on the profile's declaration that the row exists and the control's actor
// may change it. Windows are what two marks' ledger reads see (pg-actor windowLedger): under a snapshot mark, what
// committed between them. A tool's write that the join reads ambiguous (the user and the tool wrote the same row in one
// window) has no actor at all, so serviceRoleNotes does not name it.
//
// Wiring (NC9 item 3). A target's "supabaseRules" (src/contracts.mjs) makes the factory pass supabaseResolver as each captured
// observer's actorCapture.resolve; the evaluator (src/http-effects.mjs) notes service-role writes on a pinned clause that reads
// missing (serviceRoleSeen, as serviceRoleNotes reads them) and judges rls-zero-row per declared control from the window's
// zeroRowFacts, FAIL-only, after every other stage. rlsZeroRow below is the same rule over one window, kept for these tests.
import { resolveActor, sourceValue, effectiveRole } from './pg-actor.mjs';
import { evaluateEffectAssertion, matches } from './events.mjs';

export const SUPABASE_RULES_SCHEMA = 'scopehaven-supabase-rules/1';
export const SUPABASE_REASONS = Object.freeze(['service-role-write', 'rls-zero-row', 'response-not-decided']);
export const SERVICE_ACTOR_PREFIX = 'unlisted:tool:';
export const RLS_ZERO_ROW_CHECK = 'SUPABASE-RLS-ZERO-ROW';
// The roles that bypass row-level security on a Supabase stack (service_role and postgres have BYPASSRLS; supabase_admin
// is the superuser).
export const DEFAULT_SERVICE_ROLES = Object.freeze(['service_role', 'postgres', 'supabase_admin']);
const TOOL = /^[A-Za-z0-9_-]{1,80}$/, ROLE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/, CHECK_ID = /^[A-Za-z0-9_-]{1,80}$/;
const WRITES = ['POST', 'PUT', 'PATCH', 'DELETE'];
const UNSAFE_KEYS = ['__proto__', 'prototype', 'constructor'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bad = message => { throw new Error(`supabase rules: ${message}`); };

// { tool, serviceRoles?, passThrough?, allowedWrites? }: tool is the declared name of the server-side identity (an id, not
// a principal); serviceRoles defaults to DEFAULT_SERVICE_ROLES; passThrough is { from: "jwt-claims" } or { from: "column" }
// (the latter needs the capture's tables to declare actorColumn); allowedWrites maps an allowed-use control's id to the
// write it should make, { table: "schema.table", op: "UPDATE" | "DELETE" }, a table the capture declares.
export function validateSupabaseRules(decl, { block } = {}) {
  if (!plain(decl) || Object.keys(decl).some(key => !['tool', 'serviceRoles', 'passThrough', 'allowedWrites'].includes(key))) bad('is { "tool", "serviceRoles"?, "passThrough"?, "allowedWrites"? }');
  if (typeof decl.tool !== 'string' || !TOOL.test(decl.tool)) bad('"tool" names the server-side identity: 1-80 letters, digits, "_" or "-"');
  if (decl.serviceRoles !== undefined && !(Array.isArray(decl.serviceRoles) && decl.serviceRoles.length >= 1 && decl.serviceRoles.length <= 8 && decl.serviceRoles.every(r => typeof r === 'string' && ROLE.test(r)) && new Set(decl.serviceRoles).size === decl.serviceRoles.length)) bad('"serviceRoles" lists 1 to 8 distinct role names');
  if (decl.passThrough !== undefined) {
    if (!plain(decl.passThrough) || Object.keys(decl.passThrough).length !== 1 || !['jwt-claims', 'column'].includes(decl.passThrough.from)) bad('"passThrough" is { "from": "jwt-claims" } or { "from": "column" }');
    if (decl.passThrough.from === 'column' && block && block.tables.some(t => t.actorColumn === undefined)) bad('"passThrough" from "column" needs every captured table\'s "actorColumn"');
  }
  if (decl.allowedWrites !== undefined) {
    if (!plain(decl.allowedWrites) || Object.keys(decl.allowedWrites).length > 64) bad('"allowedWrites" maps up to 64 control ids to { table, op }');
    const captured = block ? new Set(block.tables.map(t => `${t.schema ?? 'public'}.${t.table}`)) : null;
    for (const [id, w] of Object.entries(decl.allowedWrites)) {
      if (UNSAFE_KEYS.includes(id) || !CHECK_ID.test(id)) bad('an "allowedWrites" key is a check id');
      if (!plain(w) || Object.keys(w).length !== 2 || typeof w.table !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}\.[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(w.table) || !['UPDATE', 'DELETE'].includes(w.op)) bad('an "allowedWrites" entry is { "table": "schema.table", "op": "UPDATE" | "DELETE" }');
      if (captured && !captured.has(w.table)) bad('an "allowedWrites" table is one the actor capture declares');
    }
  }
  return decl;
}
const serviceRolesOf = decl => decl.serviceRoles ?? DEFAULT_SERVICE_ROLES;
// Was this write made under a declared service role: the claims PostgREST set, or the session's effective role (SET ROLE,
// else the login role, so a direct connection as postgres counts)?
export const isServiceWrite = (entry, decl) => serviceRolesOf(decl).includes(entry.claimsRole) || serviceRolesOf(decl).includes(effectiveRole(entry));

// (a) The resolver: the tool's for a service-role write, unless the declared pass-through names a declared principal.
export function supabaseResolver(decl) {
  if (!plain(decl)) throw new Error('supabase rules: the resolver needs the rules\' declaration');
  return (entry, block) => {
    if (!isServiceWrite(entry, decl)) return resolveActor(entry, block);
    const passed = decl.passThrough === undefined ? null : sourceValue(entry, { ...block, actor: { from: decl.passThrough.from } });
    if (passed !== null && passed !== undefined && passed !== '' && Object.hasOwn(block.principals, passed)) return { actor: block.principals[passed], via: `service-role-pass-through:${decl.passThrough.from}`, serviceRole: true, tool: decl.tool };
    return { actor: `${SERVICE_ACTOR_PREFIX}${decl.tool}`, via: 'service-role', serviceRole: true, tool: decl.tool, reason: 'service-role-write' };
  };
}
// The clauses of a check whose actor pin names a declared principal, that read missing over the check's windows, and whose
// windows hold a committed effect that fits the clause without its pin but was the tool's (a service-role write): the note
// names why the clause reads inconclusive. A clause the user's own writes decide (a pass, or a fail) gets no note.
export function serviceRoleNotes(check, windows, { principals } = {}) {
  const notes = [];
  (check.effects ?? []).forEach((clause, index) => {
    const pin = clause?.select?.actor;
    if (typeof pin !== 'string' || (principals && !principals.includes(pin))) return;
    if (evaluateEffectAssertion(clause, windows).verdict !== 'missing') return;
    const { actor: _pin, ...rest } = clause.select;
    const tools = [...new Set(windows.flatMap(w => w.events ?? []).filter(e => typeof e.actor === 'string' && e.actor.startsWith(SERVICE_ACTOR_PREFIX) && matches(e, { ...rest, outcome: 'committed' }))
      .map(e => e.actor.slice(SERVICE_ACTOR_PREFIX.length)))];
    if (tools.length) notes.push({ clause: index + 1, reason: 'service-role-write', tools, basis: `A committed write this clause selects was made with a service role by ${tools.join(', ')}, which carries no end user, so the clause pinned to ${pin} cannot read that write as the user's or as anyone else's (other gaps in the window may also hold it inconclusive); declare passThrough if the application passes the user through.` });
  });
  return notes;
}

// The zero-row facts of one window (NC9 item 3), which the evaluator's rls-zero-row stage reads (src/http-effects.mjs
// zeroRowFinding; the decision is made there, under the HTTP evaluator identity, and this module's code is in the Postgres
// collectors' files): the UPDATE and DELETE statements that changed no row without another write to their table in the same
// transaction, and the writes that changed rows (one per table, operation, actor and service flag), each with the actor the
// capture's resolver names (a principal id, unlisted:<digest>, unlisted:tool:<tool> or null, never a captured value) and whether
// it was a service-role write. A window whose capture did not verify intact, or whose ledger did not read, carries none. At most
// ZERO_ROW_LISTED of each; the rest are counted (omitted).
export const ZERO_ROW_FACTS_SCHEMA = 'scopehaven-pg-zero-row/1';
export const ZERO_ROW_LISTED = 64;
export function zeroRowFacts({ entries, block, capture, resolve = resolveActor }) {
  const facts = (status, statements = [], writes = []) => ({ schema: ZERO_ROW_FACTS_SCHEMA, capture: status, statements: statements.slice(0, ZERO_ROW_LISTED), writes: writes.slice(0, ZERO_ROW_LISTED),
    omitted: { statements: Math.max(0, statements.length - ZERO_ROW_LISTED), writes: Math.max(0, writes.length - ZERO_ROW_LISTED) } });
  if (capture !== 'intact') return facts(['absent', 'altered', 'unreadable'].includes(capture) ? capture : 'unreadable');
  if (!Array.isArray(entries)) return facts('unreadable');
  const named = e => { const r = resolve(e, block); return { actor: typeof r?.actor === 'string' ? r.actor : null, serviceRole: r?.serviceRole === true }; };
  const companion = e => entries.some(o => !o.zeroRow && o.table === e.table && o.txid === e.txid);
  const statements = entries.filter(e => e.zeroRow && (e.op === 'UPDATE' || e.op === 'DELETE') && !companion(e)).map(e => ({ table: e.table, op: e.op, ...named(e), depth: e.depth }));
  const writes = new Map();
  for (const e of entries) if (!e.zeroRow) { const w = { table: e.table, op: e.op, ...named(e) }; writes.set(JSON.stringify(w), w); }
  return facts('intact', statements, [...writes.values()]);
}

// The response contract decided as success: every response assertion passed (effects and the actor-identity assertion are
// read elsewhere) on a complete response. An inconclusive predicate, a body that did not parse or an unfinished response
// is not a success the application reported.
const responseSucceeded = row => Array.isArray(row?.assertions) && row.observed?.complete === true && row.assertions.some(a => a.name === 'HTTP status matches contract')
  && row.assertions.filter(a => !/^Observed effect|^Actor identity/.test(a.name)).every(a => a.status === 'pass');

// (b) The rls-zero-row reading of one check's window. check: the profile check; row: its result row (as the connector
// writes it); entries: the window's ledger entries (pg-actor windowLedger); block: the capture; capture: the window's
// capture status (required); actors: the profile's actors; decl: these rules' declaration (required). Returns a FAIL-only
// row: fail, informational or inconclusive.
export function rlsZeroRow({ check, row, entries, block, capture, actors = {}, decl }) {
  if (!['intact', 'absent', 'altered', 'unreadable'].includes(capture)) throw new Error('supabase rules: rlsZeroRow needs the window\'s capture status');
  if (!plain(decl)) throw new Error('supabase rules: rlsZeroRow needs the rules\' declaration');
  const base = { schema: SUPABASE_RULES_SCHEMA, check: RLS_ZERO_ROW_CHECK, checkId: check.id, failOnly: true };
  if (capture !== 'intact' || !Array.isArray(entries)) return { ...base, status: 'inconclusive', verdict: 'inconclusive', reason: capture !== 'intact' ? `capture-${capture}` : 'ledger-unreadable', findings: [],
    basis: 'The actor capture did not verify intact for this window (or its ledger could not be read), so no zero-row statement can be ruled in or out. FAIL-only: this rule never passes.' };
  const resolve = supabaseResolver(decl);
  // A zero-row statement with a companion write (a row changed on the same table in the same transaction: an upsert's
  // insert, a MERGE's other action) is not a refusal.
  const companion = e => entries.some(o => !o.zeroRow && o.table === e.table && o.txid === e.txid);
  const zero = entries.filter(e => e.zeroRow && (e.op === 'UPDATE' || e.op === 'DELETE') && !companion(e)).map(e => ({ table: e.table, op: e.op, txid: e.txid, depth: e.depth, ...resolve(e, block) }));
  if (!zero.length) return { ...base, status: 'informational', verdict: 'no-zero-row-observed', reason: null, findings: [], basis: 'No UPDATE or DELETE in this window changed zero rows without another write to its table in the same transaction. That is not a pass: the rule only ever reports a refusal the application did not surface. FAIL-only: this rule never passes.' };
  const own = actors[check.actorId]?.principalId, expect = decl.allowedWrites?.[check.id];
  const findings = zero.slice(0, 64).map(z => ({ table: z.table, op: z.op, actor: z.actor, ...(z.serviceRole ? { tool: z.tool } : {}), txid: z.txid, ...(z.depth > 1 ? { depth: z.depth } : {}) }));
  const twin = check.severity === 'control' && WRITES.includes(check.method) && expect !== undefined;
  const succeeded = responseSucceeded(row);
  // The declared write, refused for the control's own actor (never a service-role statement, which bypasses row-level
  // security), at any depth (a view's INSTEAD OF trigger or an apply trigger is the declared write's path), and not made in
  // the window by a statement of that table and operation of the control's own actor or the declared tool. Another
  // principal's write of the table does not stand in for it, but is named on the finding: an idempotent request that
  // matched nothing because someone else already made the change reads the same.
  const mine = twin ? zero.filter(z => !z.serviceRole && own !== undefined && z.actor === own && z.table === expect.table && z.op === expect.op) : [];
  const writers = twin ? entries.filter(e => !e.zeroRow && e.table === expect.table && e.op === expect.op).map(e => resolve(e, block)) : [];
  // A write no one is named for may be the control's own (NC9 item 3, PR520 review MINOR 1): it suppresses the FAIL too.
  const made = writers.some(r => r.serviceRole || r.actor === null || (own !== undefined && r.actor === own));
  const others = [...new Set(writers.filter(r => !r.serviceRole && r.actor !== null && !(own !== undefined && r.actor === own)).map(r => r.actor))].slice(0, 8);
  if (twin && succeeded && mine.length && !made) return { ...base, status: 'fail', verdict: 'fail', reason: 'rls-zero-row', findings, ...(others.length ? { alsoWrittenBy: others } : {}),
    basis: `The allowed-use control's declared ${expect.op} on ${expect.table} under ${own}'s own session changed no row${mine.every(z => z.depth > 1) ? ' (in a statement a trigger the request fired issued)' : ''}, and neither ${own} nor the tool made that write in the window, while the response reported success: a refusal (row-level security, or a predicate that matched nothing) the application did not surface.${others.length ? ' Another principal wrote this table in the window (alsoWrittenBy); an idempotent request that matched nothing because the change was already made reads the same.' : ''} FAIL-only: this rule never passes.`.slice(0, 1200) };
  const why = check.severity !== 'control' ? 'the check is a boundary check, where a statement that changes nothing is the refusal working'
    : !WRITES.includes(check.method) ? 'the control does not write'
    : expect === undefined ? 'the control declares no expected write (allowedWrites)'
    : !succeeded ? 'the response did not decide a success (a refusal the application surfaced, an unfinished response or an undecided predicate)'
    : made ? 'the declared write was made by another statement in the window'
    : 'no zero-row statement is the control\'s own actor\'s declared write';
  return { ...base, status: 'informational', verdict: 'rls-zero-row-informational', reason: twin && !succeeded ? 'response-not-decided' : 'rls-zero-row', findings,
    basis: `${zero.length} UPDATE or DELETE statement${zero.length === 1 ? '' : 's'} in this window changed no row; informational because ${why}. FAIL-only: this rule never passes.`.slice(0, 1200) };
}
