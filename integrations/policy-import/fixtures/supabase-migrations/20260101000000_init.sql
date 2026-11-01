-- Synthetic Supabase-style schema for policy-import tests. No real data.
create table public.profiles (
  id uuid primary key,
  owner_id uuid not null,
  display_name text
);
alter table public.profiles enable row level security;

create policy "Profiles are readable by their owner"
  on public.profiles for select
  to authenticated
  using ( (select auth.uid()) = owner_id );

create policy "Owners insert their profile"
  on public.profiles for insert
  to authenticated
  with check ( (select auth.uid()) = owner_id );

create table public.announcements (id bigint primary key, body text);
alter table public.announcements enable row level security;
create policy "Announcements are public" on public.announcements for select using (true);

create table public.audit_log (id bigint primary key, entry text);
