// Write-plan confirmation (goal 03, scopehaven-write-confirmation/1). As with draft confirmation (draft.mjs), the planId
// only detects careless edits, since anyone can recompute it. So confirmation re-derives the plan from the statement,
// binding and matrices it came from and accepts only an identical planId, then re-checks every case property on the
// case itself as a second line. The confirmedBy label is free text the caller supplies: it authenticates no one. A
// confirmed plan is still not executed coverage; nothing here sends a request.
import { canonical, sha256 } from './matrix.mjs';
import { CASE_LIMITS, TEMPLATES, WRITE_PLAN_SCHEMA, buildWritePlan, verifyPlanId } from './write-plan.mjs';
import { routeFor, validateWriteBinding } from './write-binding.mjs';

export const WRITE_CONFIRMATION_SCHEMA = 'scopehaven-write-confirmation/1';
const fail = message => { throw new Error(`write confirmation: ${message}`); };
const VEHICLE_OF = { T4: 'P', T5: 'S' };
const CONTROL_PARTS = ['pair', 'control', 'liveness', 'before-control', 'peer-twin'];
const PARTS = ['attempt', 'transition', 'padding', ...CONTROL_PARTS];

// Every property a case promises, checked on the case itself against the binding.
export function checkPlanCases(plan, binding) {
  const b = validateWriteBinding(binding);
  if (plan?.schema !== WRITE_PLAN_SCHEMA || !Array.isArray(plan.cases)) fail('a write plan is required');
  const ids = new Set();
  for (const c of plan.cases) {
    const bad = why => fail(`case ${c?.caseId ?? '?'} ${why}, so it was not drafted from the statement as recorded`);
    if (!/^WC-[0-9A-F]{12}$/.test(c?.caseId ?? '') || ids.has(c.caseId)) bad('has an invalid or repeated id');
    ids.add(c.caseId);
    if (!Object.hasOwn(TEMPLATES, c.template) || c.vehicle !== (VEHICLE_OF[c.template] ?? 'P')) bad('has a template or vehicle its template does not allow');
    if (c.confirmed !== false) bad('is marked confirmed');
    // A deny is drafted as a prohibition and an allow is not, whatever template produced the case.
    if (!['allow', 'deny'].includes(c.decision) || (c.decision === 'deny') !== (Array.isArray(c.assertions) && c.assertions.some(a => a?.kind === 'effect.none'))) bad('has a shape that contradicts its stated decision (a deny needs a prohibition, an allow has none)');
    if (!Array.isArray(c.turns) || !c.turns.length || c.turns.length > CASE_LIMITS.turns) bad(`has more than ${CASE_LIMITS.turns} turns or none`);
    const route = routeFor(b, c.variant?.resource, c.variant?.action);
    if (!route) bad('acts on a route the binding does not bind');
    for (const t of c.turns) {
      if (!PARTS.includes(t.part)) bad(`has a turn of unknown part ${t.part}`);
      const r = routeFor(b, t.resource, t.action);
      if (!r || r.method !== t.method || r.pathTemplate !== t.pathTemplate) bad('has a turn whose method or path is not its bound route\'s');
      if (t.method === 'GET' && t.body !== undefined) bad('sends a body with a GET');
      if (t.part === 'padding' && t.method !== 'GET') bad('pads with a write');
      if (t.part === 'attempt') {
        const refusal = route.refusal.kind === 'status' ? route.refusal.statuses : [route.refusal.status];
        if (canonical(t.expect) !== canonical(refusal)) bad('expects statuses its route\'s refusal does not declare');
      }
      if (CONTROL_PARTS.includes(t.part) && canonical(t.expect) !== canonical([r.allowStatus])) bad('expects a status other than its route\'s allowed status on a control');
      if (!t.expect.every(s => Number.isInteger(s) && s < 500)) bad('expects a 5xx');
    }
    if (!Array.isArray(c.assertions) || !c.assertions.length) bad('has no assertions');
    for (const a of c.assertions) {
      if (!['effect.none', 'effect.exists'].includes(a.kind)) bad('has an assertion that is not an effect clause (json predicates are never drafted on write rows)');
      if (!Array.isArray(a.window) || a.window[0] < 1 || a.window[1] > c.turns.length || a.window[0] > a.window[1]) bad('has a window outside its turns');
      if ((a.kind === 'effect.none') !== (a.severity !== 'control')) bad('has a prohibition without a prohibition severity, or a control that is not a presence');
      if (a.kind === 'effect.none') {
        const ctl = c.assertions.find(x => x.id === a.control);
        const same = x => canonical([x.select?.source, x.select?.operation, x.select?.name, x.select?.resourceTemplate ?? null]);
        if (!ctl || ctl.kind !== 'effect.exists' || ctl.severity !== 'control' || same(ctl) !== same(a)) bad('has a prohibition without its paired control on the same effect');
      }
    }
    for (const actor of new Set(c.assertions.map(a => a.select?.actorRef))) if (c.turns.filter(t => t.actor === actor).length < CASE_LIMITS.judgedTurns) bad(`gives judged actor ${actor} fewer than ${CASE_LIMITS.judgedTurns} turns`);
  }
}

// Confirm a plan: re-derive it, accept only an identical planId, re-check every case, and seal the record.
export function confirmWritePlan(plan, { statement, binding, matrices = [], confirmedBy, now = new Date() } = {}) {
  if (!verifyPlanId(plan)) fail('the plan is missing or was edited after it was built (its planId no longer matches)');
  if (plan.confirmed !== false) fail('this plan is already marked confirmed');
  if (typeof confirmedBy !== 'string' || !confirmedBy.trim() || confirmedBy.length > 120 || /[\u0000-\u001f\u007f]/.test(confirmedBy)) fail('confirmedBy is a label (1 to 120 characters); it authenticates no one');
  if (!plan.cases.length) fail('the plan has no cases to confirm');
  if (buildWritePlan({ statement, binding, matrices }).planId !== plan.planId) fail('the plan is not what this statement, binding and matrices produce, so it was not drafted from them as recorded');
  checkPlanCases(plan, binding);
  const body = { schema: WRITE_CONFIRMATION_SCHEMA, planId: plan.planId, statementId: plan.statementId, bindingDigest: plan.bindingDigest, inventoryDigest: plan.inventoryDigest,
    application: plan.application, confirmedBy: confirmedBy.trim(), confirmedAt: now.toISOString(),
    cases: plan.cases.map(c => ({ caseId: c.caseId, key: c.key, template: c.template, vehicle: c.vehicle, caseDigest: sha256(canonical(c)) })), warnings: plan.warnings };
  return { ...body, recordDigest: sha256(canonical(body)) };
}

export function verifyWriteConfirmation(record) {
  if (record === null || typeof record !== 'object' || typeof record.recordDigest !== 'string') return false;
  const { recordDigest, ...body } = record;
  return record.schema === WRITE_CONFIRMATION_SCHEMA && recordDigest === sha256(canonical(body));
}
