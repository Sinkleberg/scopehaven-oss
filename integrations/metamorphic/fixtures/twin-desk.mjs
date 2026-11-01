// Test-only twin desk for the tenant-swap relation: a two-tenant billing desk (synthetic, in memory) whose task code
// is a fixed script (no model), in one fixed build and four defective ones. Each task returns the desk's whole state
// before and after it ran, and the webhooks it would send; the tests send those through a real egress recorder.
//   fixed        every effect is scoped to the actor's own tenant
//   leak         a cross-tenant leak that is asymmetric: credits land on the first tenant's account, which is the
//                actor's own only for one tenant
//   side-effect  a tenant-scoped side effect: under one tenant, closing a ticket also deletes that tenant's drafts
//   symmetric    a symmetric swap bug: each tenant's credit lands on the other tenant's account (the swap relation
//                is satisfied; only the complementary TENANT check sees it)
//   hardcoded    the webhook destination is hard-coded to the first tenant's hook host
// Ids and timestamps come from a seeded counter and a fake clock, so runs are reproducible and still differ by run.
export const TENANTS = Object.freeze(['acme', 'globex']);
export const ACTORS = Object.freeze({ ana: { principal: 'user-ana', tenant: 'acme' }, gil: { principal: 'user-gil', tenant: 'globex' } });
export const BUILDS = Object.freeze(['fixed', 'leak', 'side-effect', 'symmetric', 'hardcoded']);
export const HOOK_HOST = tenant => `${tenant}.hooks.example`;
export const TASKS = Object.freeze(['credit', 'open-ticket', 'close-ticket', 'rename', 'noop']);

export function seedState() {
  return {
    accounts: TENANTS.map(t => ({ id: `acct-${t}`, tenantId: t, balance: 100, updatedAt: '2026-10-01T00:00:00.000Z' })),
    tickets: TENANTS.flatMap(t => [
      { id: `tk-${t}-1`, tenantId: t, status: 'open', title: 'Synthetic ticket', updatedAt: '2026-10-01T00:00:00.000Z' },
      { id: `tk-${t}-draft`, tenantId: t, status: 'draft', title: 'Synthetic draft', updatedAt: '2026-10-01T00:00:00.000Z' }]),
    credits: [],
    audit: [],
  };
}

// One run of one task: { before, after, sends: [{ host, path, body }] }. `seed` varies generated ids and times.
export function runTask(build, actorId, task, { seed = 1 } = {}) {
  if (!BUILDS.includes(build) || !Object.hasOwn(ACTORS, actorId) || !TASKS.includes(task)) throw new Error('Unknown build, actor or task.');
  const actor = ACTORS[actorId], state = seedState(), before = structuredClone(state), sends = [];
  let n = seed * 1000;
  const id = prefix => `${prefix}-${(n++).toString(36)}-${seed}`;
  const now = () => new Date(Date.parse('2026-10-24T00:00:00.000Z') + (n++) * 7).toISOString();
  const other = TENANTS.find(t => t !== actor.tenant);
  const accountFor = () => (build === 'leak' ? state.accounts[0] : build === 'symmetric' ? state.accounts.find(a => a.tenantId === other) : state.accounts.find(a => a.tenantId === actor.tenant));
  const hook = (path, body) => sends.push({ host: build === 'hardcoded' ? HOOK_HOST(TENANTS[0]) : HOOK_HOST(actor.tenant), path, body: { ...body, event_id: id('evt') } });
  if (task === 'credit') {
    const account = accountFor();
    account.balance += 25; account.updatedAt = now();
    state.credits.push({ id: id('cr'), tenantId: account.tenantId, account: account.id, amount: 25, by: actor.principal, createdAt: now() });
    state.audit.push({ tenantId: actor.tenant, action: 'credit' });
    hook('/v1/events', { type: 'credit.created', tenant: actor.tenant, wallet: account.id, amount: 25 });
  } else if (task === 'open-ticket') {
    state.tickets.push({ id: id('tk'), tenantId: actor.tenant, status: 'open', title: 'New synthetic ticket', updatedAt: now() });
    state.audit.push({ tenantId: actor.tenant, action: 'ticket.open' });
  } else if (task === 'close-ticket') {
    const ticket = state.tickets.find(t => t.id === `tk-${actor.tenant}-1`);
    ticket.status = 'closed'; ticket.updatedAt = now();
    if (build === 'side-effect' && actor.tenant === TENANTS[1]) state.tickets = state.tickets.filter(t => !(t.tenantId === actor.tenant && t.status === 'draft'));
    state.audit.push({ tenantId: actor.tenant, action: 'ticket.close' });
    hook('/v1/events', { type: 'ticket.closed', tenant: actor.tenant, ticket: ticket.id });
  } else if (task === 'rename') {
    // Touches only an ignorable column when declared so: the timestamp moves, the title is written unchanged.
    const ticket = state.tickets.find(t => t.id === `tk-${actor.tenant}-1`);
    ticket.title = 'Synthetic ticket'; ticket.updatedAt = now();
  }
  return { before, after: structuredClone(state), sends };
}
