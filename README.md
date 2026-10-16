# Auth.i

Auth.i's first Docker deployment foundation runs two isolated roles: the Node.js HTTP service and
Postgres 17. Postgres is reachable only on the private Compose network and stores its data in a
named volume. The HTTP port binds to loopback so an existing TLS reverse proxy can reach it without
publishing it directly to the internet.

This checkout currently provides configuration loading and a database-backed `/healthz` endpoint.
Authentication, migrations, bootstrap-admin creation, OIDC, forward-auth, and the REST API are not
implemented yet, so this deployment is infrastructure groundwork rather than a usable identity
provider.

## Start

No environment file is required for a fresh local deployment:

```sh
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:9000/healthz
```

On first start, Compose creates a random Postgres password and Auth.i creates a random encryption
key. Both are kept in the persistent `authi-data` volume. The local issuer URL defaults to
`http://localhost:9000`. The health endpoint returns `{"status":"ok"}` while Postgres is reachable.
The app waits for Postgres's health check before starting. To inspect logs or stop the deployment:

```sh
docker compose logs -f authi
docker compose down
```

`docker compose down` preserves the `postgres-data` volume. To delete the database as well, remove
that volume explicitly with `docker compose down --volumes`.

This checkout still has no in-app settings or authentication UI; it only provides configuration
loading and `/healthz`. Until those screens are implemented, optional `.env` overrides are available
for deployments behind a reverse proxy. When reusing a database volume created by an older version,
keep its original `POSTGRES_PASSWORD` available in `.env` so the generated password file matches it.

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

- `authi`: non-root Node.js 24 service; HTTP port 9000 is published only on `127.0.0.1` for the
  host's TLS reverse proxy.
- `postgres`: Postgres 17; no host port is published, and persistent files live in `postgres-data`.

Both services use a dedicated private bridge network. Change `AUTHI_HOST_PORT` if port 9000 is
already occupied. Do not expose the service directly to the internet; terminate TLS at the existing
reverse proxy.