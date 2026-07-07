-- ============================================================
-- Job Collectives / TJC Portal — PIN Rate Limiting
-- Project ref: gezslcbdhxuvqyfnalfs
--
-- Run this AFTER 0001_secure_pin_auth.sql.
-- Adds a lockout mechanism to verify_login_pin and set_login_pin so
-- the anon-reachable RPCs can no longer be brute-forced.
--
-- Policy: 5 failed attempts on an account -> locked for 15 minutes.
-- A successful check resets the counter. Both the login PIN check
-- and the "current PIN" check inside a PIN change share the same
-- counter per account, since both are guessable surfaces.
-- ============================================================

-- 1. Attempts table -----------------------------------------------------------
create table if not exists public.login_attempts (
  key              text primary key,       -- '<table>:<row_id>'
  failed_count     int  not null default 0,
  locked_until     timestamptz,
  last_attempt_at  timestamptz not null default now()
);

alter table public.login_attempts enable row level security;
-- No policies for anon/authenticated: only reachable via the
-- SECURITY DEFINER functions below.
revoke all on public.login_attempts from anon, authenticated;

-- 2. Internal helpers -----------------------------------------------------------
-- Checks whether an account is currently locked out. Read-only.
create or replace function public._pin_attempt_gate(p_key text)
returns table(allowed boolean, retry_after timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  select * into rec from public.login_attempts where key = p_key;
  if rec.key is not null and rec.locked_until is not null and rec.locked_until > now() then
    return query select false, rec.locked_until;
  end if;
  return query select true, null::timestamptz;
end;
$$;

-- Records the outcome of an attempt and applies the lockout policy.
create or replace function public._pin_attempt_record(p_key text, p_success boolean)
returns table(locked boolean, retry_after timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  max_attempts constant int := 5;
  lockout_minutes constant int := 15;
  rec record;
  new_locked_until timestamptz;
begin
  if p_success then
    insert into public.login_attempts (key, failed_count, locked_until, last_attempt_at)
      values (p_key, 0, null, now())
    on conflict (key) do update
      set failed_count = 0, locked_until = null, last_attempt_at = now();
    return query select false, null::timestamptz;
  end if;

  insert into public.login_attempts (key, failed_count, last_attempt_at)
    values (p_key, 1, now())
  on conflict (key) do update
    set failed_count = public.login_attempts.failed_count + 1,
        last_attempt_at = now()
  returning * into rec;

  if rec.failed_count >= max_attempts then
    new_locked_until := now() + make_interval(mins => lockout_minutes);
    update public.login_attempts set locked_until = new_locked_until where key = p_key;
    return query select true, new_locked_until;
  end if;

  return query select false, null::timestamptz;
end;
$$;

-- 3. Re-create verify_login_pin with the lockout gate ---------------------------
-- Must drop first: the return shape (OUT columns) is changing from
-- 0001's (ok, id, display_name, role, initials, color) to add
-- (locked, retry_after), and Postgres does not allow CREATE OR REPLACE
-- to change a function's return type.
drop function if exists public.verify_login_pin(text, text, text);

create or replace function public.verify_login_pin(p_table text, p_row_id text, p_pin text)
returns table(ok boolean, id text, display_name text, role text, initials text, color text,
              locked boolean, retry_after timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
  gate record;
  outcome record;
  the_key text;
begin
  if p_table not in ('mgmt_users', 'hr_accounts') then
    raise exception 'invalid table';
  end if;

  the_key := p_table || ':' || p_row_id;

  select * into gate from public._pin_attempt_gate(the_key);
  if not gate.allowed then
    return query select false, null::text, null::text, null::text, null::text, null::text,
                        true, gate.retry_after;
    return;
  end if;

  if p_table = 'mgmt_users' then
    select m.id, m.display_name, m.role, m.initials, m.color, m.pin_hash
      into rec from public.mgmt_users m where m.id = p_row_id;
  else
    select h.id, h.display_name, 'hr'::text as role, h.initials, h.color, h.pin_hash
      into rec from public.hr_accounts h where h.id = p_row_id;
  end if;

  if rec.id is not null and rec.pin_hash is not null and rec.pin_hash = crypt(p_pin, rec.pin_hash) then
    select * into outcome from public._pin_attempt_record(the_key, true);
    return query select true, rec.id, rec.display_name, rec.role, rec.initials, rec.color,
                        false, null::timestamptz;
  else
    select * into outcome from public._pin_attempt_record(the_key, false);
    return query select false, null::text, null::text, null::text, null::text, null::text,
                        outcome.locked, outcome.retry_after;
  end if;
end;
$$;

grant execute on function public.verify_login_pin(text, text, text) to anon, authenticated;

-- 4. Re-create set_login_pin with the same lockout gate --------------------------
-- Must drop first: 0001 returned a bare boolean, this version returns
-- a table(ok, locked, retry_after) — again, not a compatible in-place
-- return-type change for CREATE OR REPLACE.
drop function if exists public.set_login_pin(text, text, text, text);

create or replace function public.set_login_pin(p_table text, p_row_id text, p_old_pin text, p_new_pin text)
returns table(ok boolean, locked boolean, retry_after timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
  gate record;
  outcome record;
  the_key text;
begin
  if p_table not in ('mgmt_users', 'hr_accounts') then
    raise exception 'invalid table';
  end if;
  if p_new_pin !~ '^[0-9]{6}$' then
    raise exception 'PIN must be exactly 6 digits';
  end if;

  the_key := p_table || ':' || p_row_id;

  select * into gate from public._pin_attempt_gate(the_key);
  if not gate.allowed then
    return query select false, true, gate.retry_after;
    return;
  end if;

  if p_table = 'mgmt_users' then
    select id, pin_hash into rec from public.mgmt_users where id = p_row_id;
  else
    select id, pin_hash into rec from public.hr_accounts where id = p_row_id;
  end if;

  if rec.id is null or rec.pin_hash is null or rec.pin_hash <> crypt(p_old_pin, rec.pin_hash) then
    select * into outcome from public._pin_attempt_record(the_key, false);
    return query select false, outcome.locked, outcome.retry_after;
    return;
  end if;

  select * into outcome from public._pin_attempt_record(the_key, true);

  if p_table = 'mgmt_users' then
    update public.mgmt_users set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = p_row_id;
  else
    update public.hr_accounts set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = p_row_id;
  end if;

  return query select true, false, null::timestamptz;
end;
$$;

grant execute on function public.set_login_pin(text, text, text, text) to anon, authenticated;

-- ============================================================
-- Note: return shapes changed for both functions —
--   verify_login_pin now also returns (locked, retry_after)
--   set_login_pin now returns (ok, locked, retry_after) instead of a bare boolean
-- The matching portal.html client code is updated in the same
-- commit as this migration.
-- ============================================================
