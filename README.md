# Keystone

Self-hosted single sign-on for your own apps. Keystone is an OpenID Connect provider and a forward-auth
endpoint for Traefik, Caddy and nginx, backed by Postgres and managed through a REST API.

Status: plan 1 of 4 (local users). Next: AD/Entra sign-in sources, SCIM provisioning, admin UI.

The Docker deployment runs two isolated roles: the Node.js HTTP service and Postgres 17. Postgres is
reachable only on the private Compose network and stores its data in a named volume. The HTTP port
binds to loopback so an existing TLS reverse proxy can reach it without publishing it directly to the
internet.

## Start

No environment file is required for a fresh local deployment. To create the first admin on first
start, pass the bootstrap variables (or put them in `.env`, see `.env.example`):

```sh
KEYSTONE_BOOTSTRAP_ADMIN_USER=admin KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password' \
  docker compose up -d --build
docker compose ps
curl http://127.0.0.1:9000/healthz
docker compose exec keystone node dist/cli.js create-api-token laptop
```

On first start, Compose creates a random Postgres password and Keystone creates a random encryption
key. Both are kept in the persistent `authi-data` volume. Keystone applies its database migrations
on every start. The bootstrap admin is created only while the database has no users; it never resets
an existing password. The local issuer URL defaults to `http://localhost:9000`. The health endpoint
returns `{"status":"ok"}` while Postgres is reachable and `503 {"status":"unavailable"}` otherwise.
The app waits for Postgres's health check before starting. To inspect logs or stop the deployment:

```sh
docker compose logs -f keystone
docker compose down
```

`docker compose down` preserves the `postgres-data` volume. To delete the database as well, remove
that volume explicitly with `docker compose down --volumes`.

**Back up the `authi-data` volume.** It holds `secret.key`; losing it makes the OIDC signing keys and
client secrets undecryptable and Keystone will no longer start against that database. Do not set or
change `KEYSTONE_SECRET_KEY` after first start for the same reason.

Optional `.env` overrides are available for deployments behind a reverse proxy (see `.env.example`).
Put Keystone behind your reverse proxy with TLS at `KEYSTONE_ISSUER_URL`. When reusing a database
volume created by an older version, keep its original `POSTGRES_PASSWORD` available in `.env` so the
generated password file matches it.

Admin commands run inside the container:

```sh
docker compose exec keystone node dist/cli.js create-api-token <name>
docker compose exec keystone node dist/cli.js create-admin <username> [email]
docker compose exec keystone node dist/cli.js reset-password <username-or-email>
```

## Connect an app with OIDC

```bash
curl -X POST https://auth.example.com/api/v1/applications \
  -H "Authorization: Bearer $KEYSTONE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"grafana","name":"Grafana","oidcEnabled":true,
       "redirectUris":["https://grafana.example.com/login/generic_oauth"],
       "launchUrl":"https://grafana.example.com"}'
```

The response holds `clientSecret` (shown once). Configure the app with:

| Setting | Value |
|---|---|
| Issuer / discovery | `<KEYSTONE_ISSUER_URL>/oidc`, e.g. `https://auth.example.com/oidc` (`/.well-known/openid-configuration`) |
| Client ID | the slug |
| Scopes | `openid profile email groups` (add `offline_access` if the app asks for it) |
| Groups claim | `groups` |

The issuer is always `KEYSTONE_ISSUER_URL` plus `/oidc`. Restrict access with
`"allowedGroupIds": ["<group id>"]`.

## Protect an app without OIDC (forward-auth)

Create the app with `"forwardAuthEnabled": true, "externalHost": "wiki.example.com"`, then point the
proxy's auth subrequest at `/outpost/auth`.

The examples use `keystone:9000`, which resolves only for a proxy attached to the `keystone-internal`
Compose network. A proxy running on the host uses the loopback port instead:
`http://127.0.0.1:${KEYSTONE_HOST_PORT}` (default `http://127.0.0.1:9000`).

The proxy **must overwrite, not append to,** `X-Forwarded-Host` with the host it routed on. Keystone
returns `400` when `X-Forwarded-Host` holds more than one value.

Traefik: see the commented labels in `docker-compose.yml` and add the `keystone` middleware to the
app's router. Traefik must join `keystone-internal` or target the loopback port.

Caddy:
```
wiki.example.com {
  forward_auth keystone:9000 {   # host proxy: forward_auth 127.0.0.1:9000
    uri /outpost/auth
    header_up X-Forwarded-Host {host}
    copy_headers X-Keystone-User X-Keystone-Email X-Keystone-Name X-Keystone-Groups X-Keystone-Uid
  }
  reverse_proxy wiki:8080
}
```

nginx:
```
# host proxy: proxy_pass http://127.0.0.1:9000/outpost/auth?mode=nginx;
location = /keystone { internal; proxy_pass http://keystone:9000/outpost/auth?mode=nginx;
  proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Uri $request_uri;
  proxy_set_header X-Forwarded-Proto $scheme; proxy_pass_request_body off; proxy_set_header Content-Length ""; }
location / { auth_request /keystone; error_page 401 = @login;
  auth_request_set $keystone_user $upstream_http_x_keystone_user; proxy_set_header X-Keystone-User $keystone_user;
  proxy_pass http://wiki:8080; }
location @login { return 302 https://auth.example.com/login?rd=$scheme://$host$request_uri; }
```

Keystone sets `X-Keystone-User`, `X-Keystone-Email`, `X-Keystone-Name`, `X-Keystone-Groups` and
`X-Keystone-Uid`. `X-Keystone-Name` and each entry of the comma-separated `X-Keystone-Groups` are
URL-encoded; decode them in the app. The app host must sit under `KEYSTONE_COOKIE_DOMAIN` so the
browser sends the Keystone session cookie.

## API

All endpoints live under `/api/v1` and need `Authorization: Bearer <token>`: `users`, `groups`,
`groups/{id}/members/{userId}`, `applications`, `applications/{id}/secret`, `api-tokens`, `audit-log`,
`keys/rotate`. Errors use `application/problem+json`. Create the first token with the
`create-api-token` CLI command above; tokens start with `keystone_`.

## Browser mock

To preview the sign-in and dashboard experience without starting Postgres, run:

```sh
npm run mock
```

Open `http://127.0.0.1:4173`. The mock includes sample user and admin accounts, a user dashboard,
and a compact admin view. Use the demo password shown on the sign-in page. All data and actions are
browser-only and reset on reload; this is a visual prototype, not real authentication or an API.
The preview server binds only to loopback.

## Service roles

- `keystone`: non-root Node.js 24 service; HTTP port 9000 is published only on `127.0.0.1` for the
  host's TLS reverse proxy.
- `postgres`: Postgres 17; no host port is published, and persistent files live in `postgres-data`.

Both services use a dedicated private bridge network. Change `KEYSTONE_HOST_PORT` if port 9000 is
already occupied. Do not expose the service directly to the internet; terminate TLS at the existing
reverse proxy.

## Development

```bash
npm install
npm run db:test:up   # Postgres for tests on port 55432
npm test
```
