-- ============================================================
-- Job Collectives / TJC Portal — Secure PIN Auth Migration
-- Project ref: gezslcbdhxuvqyfnalfs
-- (the project portal.html actually connects to)
--
-- Run this in the Supabase SQL Editor for this project:
-- Dashboard -> SQL Editor -> New query -> paste this file -> Run.
-- Safe to re-run.
--
-- What this does:
--  1. Creates/repairs mgmt_users and hr_accounts tables with a
--     pin_hash column (bcrypt via pgcrypto) instead of plaintext pin.
--  2. Migrates any existing plaintext `pin` column into pin_hash,
--     then drops the plaintext column.
--  3. Locks both tables down with RLS + revoked grants, so the
--     anon key can never read pin_hash directly.
--  4. Adds two SECURITY DEFINER functions — verify_login_pin and
--     set_login_pin — which are the ONLY way the app can check or
--     change a PIN. The hash itself never leaves the database.
-- ============================================================

create extension if not exists pgcrypto;

-- 1. Management (Founder/Owner) accounts -----------------------------------
create table if not exists public.mgmt_users (
  id            text primary key,
  username      text unique not null,
  display_name  text not null,
  role          text not null default 'owner',
  initials      text,
  color         text,
  pin_hash      text,
  created_at    timestamptz not null default now()
);

do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'mgmt_users' and column_name = 'pin') then
    update public.mgmt_users
      set pin_hash = crypt(pin, gen_salt('bf'))
      where pin is not null and (pin_hash is null or pin_hash = '');
    alter table public.mgmt_users drop column pin;
  end if;
end $$;

-- 2. HR accounts -------------------------------------------------------------
create table if not exists public.hr_accounts (
  id            text primary key,
  username      text unique not null,
  display_name  text not null,
  initials      text,
  color         text,
  pin_hash      text,
  created_at    timestamptz not null default now()
);

do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'hr_accounts' and column_name = 'pin') then
    update public.hr_accounts
      set pin_hash = crypt(pin, gen_salt('bf'))
      where pin is not null and (pin_hash is null or pin_hash = '');
    alter table public.hr_accounts drop column pin;
  end if;
end $$;

-- Seed default accounts only if the tables are empty (first run)
insert into public.mgmt_users (id, username, display_name, role, initials, color, pin_hash)
select 'u1', 'justine', 'Justine Inacay', 'owner', 'JI', '#131DBF', crypt('000000', gen_salt('bf'))
where not exists (select 1 from public.mgmt_users);

insert into public.hr_accounts (id, username, display_name, initials, color, pin_hash)
select 'hr1', 'hr', 'HR Team', 'HR', '#8B5CF6', crypt('000000', gen_salt('bf'))
where not exists (select 1 from public.hr_accounts);

-- 3. Lock both tables down completely from the client -----------------------
alter table public.mgmt_users enable row level security;
alter table public.hr_accounts enable row level security;
-- No policies are created for anon/authenticated, so direct REST access
-- (including reading pin_hash) is denied by default. Only the
-- SECURITY DEFINER functions below, or the service_role key, can
-- read or write these tables.
revoke all on public.mgmt_users from anon, authenticated;
revoke all on public.hr_accounts from anon, authenticated;

-- 4. Server-side PIN verification --------------------------------------------
create or replace function public.verify_login_pin(p_table text, p_row_id text, p_pin text)
returns table(ok boolean, id text, display_name text, role text, initials text, color text)
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  if p_table not in ('mgmt_users', 'hr_accounts') then
    raise exception 'invalid table';
  end if;

  if p_table = 'mgmt_users' then
    select m.id, m.display_name, m.role, m.initials, m.color, m.pin_hash
      into rec from public.mgmt_users m where m.id = p_row_id;
  else
    select h.id, h.display_name, 'hr'::text as role, h.initials, h.color, h.pin_hash
      into rec from public.hr_accounts h where h.id = p_row_id;
  end if;

  if rec.id is not null and rec.pin_hash is not null and rec.pin_hash = crypt(p_pin, rec.pin_hash) then
    return query select true, rec.id, rec.display_name, rec.role, rec.initials, rec.color;
  else
    return query select false, null::text, null::text, null::text, null::text, null::text;
  end if;
end;
$$;

grant execute on function public.verify_login_pin(text, text, text) to anon, authenticated;

-- 5. Server-side PIN change (requires the current PIN) -----------------------
create or replace function public.set_login_pin(p_table text, p_row_id text, p_old_pin text, p_new_pin text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  if p_table not in ('mgmt_users', 'hr_accounts') then
    raise exception 'invalid table';
  end if;
  if p_new_pin !~ '^[0-9]{6}$' then
    raise exception 'PIN must be exactly 6 digits';
  end if;

  if p_table = 'mgmt_users' then
    select id, pin_hash into rec from public.mgmt_users where id = p_row_id;
    if rec.id is null or rec.pin_hash is null or rec.pin_hash <> crypt(p_old_pin, rec.pin_hash) then
      return false;
    end if;
    update public.mgmt_users set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = p_row_id;
  else
    select id, pin_hash into rec from public.hr_accounts where id = p_row_id;
    if rec.id is null or rec.pin_hash is null or rec.pin_hash <> crypt(p_old_pin, rec.pin_hash) then
      return false;
    end if;
    update public.hr_accounts set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = p_row_id;
  end if;

  return true;
end;
$$;

grant execute on function public.set_login_pin(text, text, text, text) to anon, authenticated;

-- ============================================================
-- NOTE — residual risk / suggested follow-up:
-- These RPCs are reachable with just the public anon key (this app
-- has no full user-auth/session layer), so they should be rate-limited
-- to block PIN brute-forcing. Options once you're back in the project:
--   - Supabase Dashboard -> API -> enable rate limiting on
--     /rest/v1/rpc/verify_login_pin
--   - Or add a lightweight attempts table + lockout check inside
--     verify_login_pin itself (ask Claude to add this next).
-- ============================================================
