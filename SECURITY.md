# Security Policy

This repo hosts the public **job collectives™** marketing site (`index.html`) and
the **TJC Business OS** portal (`portal.html`, plus the founder entry pages
`justine.html`, `art.html`, `alvin.html`), backed by a Supabase project.

## Architecture at a glance

- `portal.html` is a static, client-side app. It talks to Supabase directly
  over the REST API using a **publishable key** (`sb_publishable_...`).
  Publishable keys are safe to ship in client code — they identify the
  project, not a privileged account, and every table they can reach is
  behind Row Level Security (RLS).
- PIN-based login (Management and HR accounts) is verified **server-side**.
  PINs are hashed with `pgcrypto` (bcrypt) and checked inside two
  `SECURITY DEFINER` Postgres functions — `verify_login_pin` and
  `set_login_pin` — defined in
  [`supabase/migrations/0001_secure_pin_auth.sql`](supabase/migrations/0001_secure_pin_auth.sql).
  The hash never leaves the database; the client only ever gets back a
  boolean plus a few non-sensitive profile fields.
- `mgmt_users` and `hr_accounts` have RLS enabled with **no policies** for
  `anon`/`authenticated`, so direct REST reads of those tables (including
  `pin_hash`) are denied by default. Only the two functions above, or a
  `service_role` key, can touch them.

## What must never be committed here

- A Supabase **secret / service_role key** (`sb_secret_...` or a JWT with
  `"role":"service_role"`). This bypasses RLS entirely — full read/write
  on every table. It belongs in a server-side secret store only
  (e.g. a Supabase Edge Function's environment), never in this repo.
- Any GitHub personal access token, `.env` file, or other credential.
  `.gitignore` in this repo blocks the common patterns, but it's not a
  substitute for care — double-check `git diff` before pushing.

If you ever paste a secret into a commit by accident: rotate it
immediately (Supabase → Project Settings → API → reset key, or GitHub →
Settings → Developer settings → revoke the token) rather than relying on
`git revert` — the value is already in history and public forever once
pushed to a public repo.

## Known residual risk

`verify_login_pin` / `set_login_pin` are callable with just the public
`anon`/publishable key (there's no full user-session layer in this app),
so they should be rate-limited to prevent PIN brute-forcing:

- Supabase Dashboard → API → enable rate limiting on
  `/rest/v1/rpc/verify_login_pin` and `/rest/v1/rpc/set_login_pin`, or
- Add an attempts/lockout table and check it inside the functions.

This has not been implemented yet — treat it as an open item.

## Reporting a vulnerability

If you find a security issue in this project, please email
**connect@jobcollectives.com** with details rather than opening a public
issue. We'll acknowledge within a few days.
