-- Synthetic two-tenant schema for the ScopeHaven Supabase + Next.js example (examples/supabase-next/).
-- It is the shape profile.json assumes: one workspace per tenant, one membership row per user with a role, and
-- notes written by members. It is an example, not a real application's schema: map your own tables onto it
-- (README.md, "What to replace"). Copied into a project's supabase/migrations it is applied by `supabase db reset`;
-- `./scopehaven policy import rls` reads it without any database.

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.memberships (
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid not null,
  role text not null check (role in ('admin', 'member')),
  primary key (workspace_id, user_id)
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  author_id uuid not null,
  title text not null,
  body text not null default ''
);

alter table public.workspaces enable row level security;
alter table public.memberships enable row level security;
alter table public.notes enable row level security;

-- A member sees its own membership rows only.
create policy "members read their own memberships" on public.memberships
  for select to authenticated
  using (user_id = auth.uid());

-- Members read the workspaces they belong to; only an admin renames one.
create policy "members read their workspaces" on public.workspaces
  for select to authenticated
  using (exists (select 1 from public.memberships m where m.workspace_id = workspaces.id and m.user_id = auth.uid()));

create policy "admins rename their workspaces" on public.workspaces
  for update to authenticated
  using (exists (select 1 from public.memberships m where m.workspace_id = workspaces.id and m.user_id = auth.uid() and m.role = 'admin'))
  with check (exists (select 1 from public.memberships m where m.workspace_id = workspaces.id and m.user_id = auth.uid() and m.role = 'admin'));

-- Notes are read by the workspace's members and written by their author only.
create policy "members read notes in their workspaces" on public.notes
  for select to authenticated
  using (exists (select 1 from public.memberships m where m.workspace_id = notes.workspace_id and m.user_id = auth.uid()));

create policy "authors add notes to their workspaces" on public.notes
  for insert to authenticated
  with check (author_id = auth.uid() and exists (select 1 from public.memberships m where m.workspace_id = notes.workspace_id and m.user_id = auth.uid()));

create policy "authors update their own notes" on public.notes
  for update to authenticated
  using (author_id = auth.uid())
  with check (author_id = auth.uid());

grant select on public.memberships to authenticated;
grant select, update on public.workspaces to authenticated;
grant select, insert, update on public.notes to authenticated;
