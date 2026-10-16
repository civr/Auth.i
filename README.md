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

Create the environment file and replace both generated secrets:

```sh
cp .env.example .env
openssl rand -base64 32
openssl rand -hex 24
```

Set `AUTHI_ISSUER_URL` to the public HTTPS URL that the reverse proxy will serve. Use the first
generated value for `AUTHI_SECRET_KEY` and the second for `POSTGRES_PASSWORD`. The database password
is hexadecimal so it can safely be embedded in `DATABASE_URL`.

Start the services:

```sh
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:9000/healthz
```

The health endpoint returns `{"status":"ok"}` only while Postgres is reachable. The app service
waits for Postgres's health check before starting. To inspect logs or stop the deployment:

```sh
docker compose logs -f authi
docker compose down
```

`docker compose down` preserves the `postgres-data` volume. To delete the database as well, remove
that volume explicitly with `docker compose down --volumes`.

## Service roles

- `authi`: non-root Node.js 24 service; HTTP port 9000 is published only on `127.0.0.1` for the
  host's TLS reverse proxy.
- `postgres`: Postgres 17; no host port is published, and persistent files live in `postgres-data`.

Both services use a dedicated private bridge network. Change `AUTHI_HOST_PORT` if port 9000 is
already occupied. Do not expose the service directly to the internet; terminate TLS at the existing
reverse proxy.