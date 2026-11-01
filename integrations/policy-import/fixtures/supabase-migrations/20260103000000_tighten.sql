-- Removes the temporary anonymous read and adds a restrictive MFA rule.
drop policy if exists "Temporary open read" on public.tickets;
create policy "Require MFA" on public.tickets as restrictive for all to authenticated
  using ((auth.jwt() ->> 'aal') = 'aal2');
