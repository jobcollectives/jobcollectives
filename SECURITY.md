# Security Policy

This is internal, proprietary software for The Job Collectives. It is not a public open-source project, but the practices below apply to anyone with repo or Supabase access (founders, contracted developers, HR).

## Reporting a vulnerability

If you find a security issue — exposed credentials, a way to bypass PIN login, access to another client's data, etc. — report it directly to **Justine Inacay** (Managing Director) or **hello@jobcollectives.com**. Do not open a public GitHub issue for security problems, since this repo (and any issue on it) is publicly readable.

## Known considerations specific to this project

### 1. Default PINs must be changed
Every account is seeded with a default 6-digit PIN until changed. At minimum, before this touches real client or business data:
- Change every founder PIN (`mgmt_users` table) from its seed value
- Change the HR account PIN (`hr_accounts` table) from `000000`
- Change default PINs (`123456`) on any newly created VA or client account before sharing login details

PINs are 6 digits (1,000,000 combinations). Verification happens server-side via Supabase RPC (`verify_login_pin`) with rate limiting and lockout after repeated failed attempts — but a default/guessable PIN bypasses that protection entirely regardless of how well the verification itself is built.

### 2. Client data isolation
Clients must never see each other's data — names, tasks, invoices, or capacity logs. This is enforced by which data the client portal queries and renders, not by database-level row security alone. Any new client-facing feature should be checked against this before shipping: does it only fetch the logged-in client's own records?

### 3. Supabase keys
- Only the **publishable/anon key** belongs in client-side code (`app.js`). This key is safe to expose — it's designed to be public — but it only works because Row Level Security policies and PIN-gated RPC functions control what it can actually do.
- The **service-role key** must never appear anywhere in this repo, in chat logs, or in any client-facing file. If it's ever pasted into a chat, treat it as compromised and rotate it immediately from the Supabase dashboard.
- If a GitHub Personal Access Token is ever needed for automation, use a fine-grained PAT scoped to `Contents: Read/write` on this specific repo only — not a classic token with broad account access.

### 4. No secrets in commits
Don't commit `.env` files, service-role keys, or GitHub tokens. If a secret is ever committed by mistake, rotating it is not optional — removing it from a later commit does not remove it from git history.

### 5. Financial data
Margin, profit, and OKR data must stay out of any client-facing view. This is a deliberate product requirement, not just a nice-to-have — check any new Owner-side financial feature isn't accidentally reachable from the client or VA portal's navigation.

## Scope

This policy covers the portal (`jobcollectives/jobcollectives`) and the marketing website (`jobcollectives/jobcollectives.github.io`). It does not cover third-party services (Supabase, GitHub Pages) — report issues with those platforms directly to their respective security teams.
