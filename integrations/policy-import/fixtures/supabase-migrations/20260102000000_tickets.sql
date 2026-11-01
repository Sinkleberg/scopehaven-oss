create table public.tickets (id bigint primary key, org_id uuid, created_by uuid, body text);
alter table public.tickets enable row level security;

create policy "Org members manage tickets" on public.tickets
  for all to authenticated
  using (org_id in (select org_id from public.memberships where user_id = auth.uid()));

create policy "Temporary open read" on public.tickets for select to anon using (true);
