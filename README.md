# TJC Business OS

Internal operations portal and public website for **The Job Collectives (TJC)** — a Filipino-led virtual assistant agency serving North American businesses.

This is proprietary software. See [`LICENSE.txt`](./LICENSE.txt).

---

## Project structure

This project is split across **two repositories**, each deployed independently via GitHub Pages:

| Repo | Purpose | Live URL |
|---|---|---|
| `jobcollectives/jobcollectives` | The portal (this repo) | `https://jobcollectives.github.io/jobcollectives/` |
| `jobcollectives/jobcollectives.github.io` | Public marketing website | `https://jobcollectives.github.io/` |

The website embeds the portal in an iframe (see `openPortal()` in the website's `index.html`) so visiting clients and partners can log in without leaving the site. Both must be deployed for that connection to work.

---

## This repo (the portal)

```
index.html      Markup shell only — loads styles.css and app.js
styles.css      All styling
app.js          All application logic (data layer, auth, all four portal views)
alvin.html      Direct-login redirect for Alvin (Director of Operations)
art.html        Direct-login redirect for Art (Director of Growth)
justine.html    Direct-login redirect for Justine (Managing Director)
```

All three files (`index.html`, `styles.css`, `app.js`) must sit in the same folder — `index.html` references the other two by relative path.

### What's inside `app.js`

One shared codebase serving four distinct views, gated by role after login:

- **Owner** — full company dashboard, Finance, HR portal access, "View As" switcher to preview Art's or Alvin's dashboard
- **Growth Director (Art)** / **Ops Director (Alvin)** — department-scoped dashboards, plus a "Partner View" switcher to see each other's department and a company-wide snapshot strip
- **VA (Partner)** — task list, timelog, SLA tracking
- **Client** — task requests, invoices, deliverables, reporting
- **HR** — employee records, onboarding, payroll, attendance

### Login

Single unified login screen — type a name or username, matching accounts across all four account types (founders, HR, VAs, clients) surface as results, selecting one routes to that account's PIN entry. There is no self-registration; **Management and HR create every account** (Team page for VAs, Clients page for clients, HR portal for HR accounts).

`alvin.html`, `art.html`, and `justine.html` bypass the search screen entirely via a `?founder=` URL parameter, dropping straight to that person's PIN pad.

---

## Data & backend

All application data is stored in **Supabase** (Postgres + REST API) — there is no localStorage fallback; the app requires an internet connection to load.

- Schema: see the SQL migration used to set up tables (`mgmt_users`, `hr_accounts`, plus one table per data type: `tasks`, `clients`, `invoices`, etc.)
- Client-side only uses the **publishable/anon key** — never the service-role key
- PIN verification happens server-side via Supabase RPC functions (`verify_login_pin`, `set_login_pin`) — PINs are never compared client-side

### Environment detection

The app only talks to Supabase when it detects a production hostname (`github.io`, `jobcollectives.com`, or `jobcollectives.io`). See `IS_PRODUCTION` / `IS_SANDBOX` near the top of the Supabase sync block in `app.js`.

---

## Deploying

1. Upload the 6 files in this repo to the repo root (branch `main`)
2. Settings → Pages → Deploy from branch → `main` / root
3. Confirm `TJC_SUPABASE_URL` and the publishable key in `app.js` match your actual Supabase project (Project Settings → API in the Supabase dashboard)

For the website repo, see its own README (or just the one `index.html` at its root — it's a single self-contained file).

---

## Security notes

See [`SECURITY.md`](./SECURITY.md) — in particular, **default PINs must be changed** before this is used with real client data.
