# Keystone settings and first-run setup (admin UI, sub-project 1 of 3)

Status: approved design, 2026-10-18. Builds on the core plan (`docs/superpowers/plans/2026-10-05-authi-core.md`) and spec (`2026-10-04-authi-design.md`).

## Goal

Deploy Keystone with **no `.env` file**. Everything an operator configures today through environment variables is set in the browser instead: a first-run setup screen creates the first admin and stores the public URL, and an admin Settings page manages the rest. Environment variables keep working as overrides for scripted deployments, but are never required.

## Admin UI roadmap (context)

1. **Setup + Settings** (this spec): settings store, `/setup`, `/admin/settings`, admin layout shell.
2. **Applications**: connect apps via OIDC or forward auth in the browser (the flow shown in the browser preview), app settings, secret rotation.
3. **People & Groups** and the user dashboard ("My apps").

Each sub-project gets its own spec, plan and implementation cycle.

## Decisions

| Topic | Decision |
|---|---|
| UI technology | Server-rendered Eta views plus small vanilla JS, same stack as the existing login page. No frontend build, no new dependencies. Styling follows the browser preview (`demo/`). |
| First admin | Setup screen protected by a one-time setup code printed in the container log. |
| Env vars | Optional overrides. If set, the env value wins and the field is shown read-only ("Set by `KEYSTONE_ISSUER_URL`"). |
| Admin access | Normal Keystone sign-in; admin pages require `users.is_admin = true`. |
| Port / bind address | Stay in Docker Compose (they are needed before the app starts). With a reverse proxy on the same VM the defaults (`127.0.0.1:9000`) need no change. |
| Secrets | Unchanged: the master key and Postgres password are generated on first start and kept in the `authi-data` volume. |

## Settings

| Key | Env override | Default | Validation | Takes effect |
|---|---|---|---|---|
| `issuerUrl` (public URL) | `KEYSTONE_ISSUER_URL` | `http://localhost:9000` | absolute `http(s)` URL, no path other than `/`, no query/fragment, no trailing slash stored; warning (not error) when `http` | live: OIDC provider reloaded |
| `cookieDomain` | `KEYSTONE_COOKIE_DOMAIN` | unset | empty, or a domain equal to or a parent of the public URL's host (leading dot allowed); at least two labels | live: read per request |
| `trustProxy` | `KEYSTONE_TRUST_PROXY` | `loopback,linklocal,uniquelocal` | `true`, `false`, or a comma list of IPs / CIDRs / `loopback` / `linklocal` / `uniquelocal` | after restart |
| `logLevel` | `LOG_LEVEL` | `info` | one of `fatal,error,warn,info,debug,trace,silent` | live |

`secureCookies` stays derived: `issuerUrl` starts with `https://`.

The bootstrap-admin variables (`KEYSTONE_BOOTSTRAP_ADMIN_*`) keep working unchanged as an alternative to the setup screen: if they create the first admin, setup is considered complete.

## Architecture

### Storage

Migration `migrations/002_settings.sql`:

```sql
CREATE TABLE settings (
  key         text PRIMARY KEY,
  value       jsonb NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL
);
```

Setup completion is derived, not stored: setup is complete when at least one user exists.

### SettingsService (`src/settings/settings.ts`)

- `load()`: reads all rows once at startup into an in-memory snapshot.
- `current(): EffectiveSettings` returns the effective value per key, in this order: env override, then database value, then default. It also reports per key whether it is locked (env) and its source.
- `update(patch, actor)`: validates the patch (zod) and rejects locked keys. It writes changed keys in one transaction, refreshes the snapshot, records an audit entry `settings.update` with old/new values, and emits `settings.changed` on the EventBus with the changed keys.
- It is a single instance per process. Multi-instance deployments are out of scope; every instance reads the DB at start.

### Consumers read settings at use time

The current `Config` stays for process-level values (secret key, database URL, port, data dir). Every consumer of `issuerUrl`, `cookieDomain`, `secureCookies` reads `settings.current()` instead of `config`:

- `src/http/context.ts`: session cookie options and redirect rules, per request.
- `src/http/csrf.ts`, login routes and forward-auth: through `context.ts`.
- `src/oidc/provider.ts`: built from `settings.current().issuerUrl`. On `settings.changed` containing `issuerUrl` or `cookieDomain`, `OidcProviderHolder.reload()` rebuilds the provider. Requests in flight finish on the old provider.
- `src/server.ts`: logger level from `current().logLevel`. On change, it sets `app.log.level`. `trustProxy` is read once at boot.

### First-run setup

- **Gate:** an `onRequest` hook in `buildApp`. While no user exists, every HTML route except `/setup`, `/healthz` and static assets redirects to `/setup`. `/api/v1` and `/oidc` return 503 problem+json `{"title":"Setup required"}`, and `/outpost/auth` returns 503.
- **Setup code:**
  - On startup with no users, Keystone generates a random code (`randomToken`, shown as 4 groups of 4 characters) and keeps only its SHA-256 hash in memory.
  - It logs at `warn` level: `Keystone setup code: XXXX-XXXX-XXXX-XXXX — open <public URL>/setup`.
  - A new code is generated on every start until setup is done. The code is never written to the DB.
- **`GET /setup`:** a card form with these fields:
  - setup code
  - public URL, prefilled from the request (`X-Forwarded-Proto` / `X-Forwarded-Host` / `Host`)
  - admin username, email, password, confirm password
- **`POST /setup`:**
  - CSRF double-submit (existing `csrf.ts`).
  - Rate limit: the existing `LoginRateLimiter` with key `setup:<ip>`, 5 attempts per 15 min; reserve-then-verify as in login.
  - Constant-time hash comparison.
  - In one transaction under `pg_advisory_xact_lock(7_424_245)` (next free constant; 7_424_242–244 are taken):
    1. re-check that no user exists
    2. create the admin (`is_admin = true`, username regex, password ≥ 12, email)
    3. save `issuerUrl` unless it is env-locked
  - After commit: emit `settings.changed`, clear the in-memory code, create a Keystone session, then redirect to `/admin/settings`. Audit: `setup.complete`.
- **After setup:** `GET /setup` and `POST /setup` return 404.

### Admin pages

- **Layout:** `views/admin/layout.eta`, with a sidebar in the style of the preview. For now it has a single "Settings" entry and the signed-in admin with "Sign out". Sub-projects 2 and 3 add entries.
- **Guard:** `requireAdmin` (`src/http/admin-guard.ts`).
  - No valid session: redirect to `/login?rd=<path>`.
  - Valid session for a non-admin: 403 page.
- **`GET /admin/settings`:** a form with the four settings.
  - Locked fields are disabled and show their env var name.
  - Each field has help text describing what it affects.
- **`POST /admin/settings`:**
  - Requires CSRF and an admin session.
  - Invalid input re-renders the form with field errors and saves nothing.
  - Success redirects to `GET /admin/settings?saved=1`, which shows a "Saved" notice.
  - When the change includes `trustProxy`, the notice is "Saved — restart Keystone to apply" with a **Restart Keystone** button.
  - Warnings on save:
    - When `issuerUrl` changed: "Connected apps must update their issuer to `<new>/oidc`."
    - When `cookieDomain` changed: existing sessions may require signing in again.
- **`POST /admin/restart`:**
  - Requires CSRF and an admin session. Records audit `system.restart`.
  - Responds with a page that says Keystone is restarting and polls `/healthz` until it is back.
  - Then calls the existing graceful shutdown and exits with code 0. Docker `restart: unless-stopped` brings the process back.
  - Outside Docker, the page says to start it again manually.
- `/` for a signed-in admin links to `/admin/settings`. The user dashboard comes in sub-project 3.

### Docker and docs

- **`docker-compose.yml`:** keeps env pass-through lines for overrides only. Comments say they are optional and that the Settings page is the normal way. No `.env` is needed for any documented setup.
- **README "Start":**
  1. `docker compose up -d`
  2. `docker compose logs keystone` to get the setup code
  3. open `/setup`

  Env vars move to an "Advanced: environment overrides" section.
- **`.env.example`:** header states it is optional and every value can be set in Settings.

## Error handling

- **Validation:** field-level messages, nothing saved, HTTP 400 with the form re-rendered.
- **Locked key in a POST** (crafted request): 400 "Set by environment".
- **DB failure while saving:** generic error page (500) with nothing partially saved (single transaction). The snapshot is refreshed only after commit.
- **OIDC reload failure** (e.g. signing keys unreadable): the old provider stays active, the error is logged, and the settings page shows "Saved, but the OIDC endpoint could not be reloaded — see logs".
- **Wrong setup code:** 400 "Setup code is incorrect". After the limit: 429 "Too many attempts, try again in 15 minutes".

## Security

- **Setup takeover:** the setup code is required, so knowing the URL is not enough. The code exists only in memory and the container log, is single-use, rate-limited, and compared in constant time. Setup runs under an advisory lock so two concurrent setups cannot both succeed.
- **Admin pages:** an admin session is required and every POST carries CSRF. The global security headers apply (CSP, `frame-ancestors 'none'`).
- **Changing `issuerUrl`:** this can break connected apps but cannot widen access. Redirect validation and cookie scoping follow the new value immediately.
- **`cookieDomain`:** it must cover the public URL's host, so cookies cannot be scoped to an unrelated domain.
- **Restart endpoint:** admin-only, CSRF-protected and audited.

## Testing

- **`SettingsService` unit tests:**
  - precedence: env over DB over default
  - locked keys rejected
  - validation of each key
  - snapshot refreshed only after commit
  - `settings.changed` emitted with the changed keys
- **Setup HTTP tests:**
  - gate redirects HTML routes and returns 503 for the API, OIDC and forward-auth endpoints
  - wrong code returns 400
  - rate limit returns 429
  - correct code creates the admin, saves the URL and signs in
  - `/setup` returns 404 afterwards
  - two concurrent setups produce exactly one admin
  - an env-locked `issuerUrl` is not overwritten
  - `KEYSTONE_BOOTSTRAP_ADMIN_*` skips setup
- **Settings HTTP tests:**
  - an admin saves
  - a non-admin gets 403
  - signed out redirects to login
  - CSRF is required
  - invalid input shows field errors
  - a locked field can't be changed
  - after an `issuerUrl` change, OIDC discovery reports the new issuer without restart
  - a `cookieDomain` change is reflected in the next `Set-Cookie`
  - a `logLevel` change applies live
- **Restart:** admin + CSRF required, audit recorded, shutdown hook invoked. Tests use a stubbed exit.
- **Docker smoke test** in an isolated project (`-p keystone-smoke`) with no `.env`:
  1. `up`
  2. read the setup code from the logs
  3. complete setup
  4. sign in
  5. change the public URL
  6. confirm discovery shows the new issuer
  7. `down -v` of the smoke project only

## Out of scope

- Applications, People and Groups screens, and the user dashboard (sub-projects 2–3).
- Cookie+CSRF auth for `/api/v1` (plan 4). Admin pages are server-rendered and don't use the REST API.
- Multi-instance settings propagation.
- Editing port or bind address from the UI.
- TOTP, upstream identity sources and SCIM (plans 2–4).
