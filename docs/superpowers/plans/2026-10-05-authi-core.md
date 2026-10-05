# Auth.i Core (Plan 1 of 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Dockerized Auth.i that gives apps SSO with local users via OIDC and forward-auth, managed through a REST API and CLI.

**Architecture:** One Fastify (Node 24, TypeScript ESM) process backed by Postgres. `oidc-provider` is mounted at `/oidc` through `@fastify/middie`; Auth.i's own session cookie (`authi_session`) is the master login session and is enforced inside the OIDC login prompt and the forward-auth endpoint. Business logic lives in small services (`src/<module>/`), HTTP routes only call services.

**Tech Stack:** Node.js 24, TypeScript 5.9 (NodeNext ESM), Fastify 5, oidc-provider 9, Kysely + pg, Postgres 17, argon2, zod 4, Eta 4, vitest, openid-client 6 (tests only), Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-04-authi-design.md`

**Plan series:** This is plan 1 of 4. Plan 2 = upstream sources (LDAPS/AD, SAML/Entra, OIDC/Entra, AD sync). Plan 3 = SCIM provisioning. Plan 4 = admin UI, user dashboard polish, `/me`, TOTP, app snippets, OpenAPI, cookie+CSRF auth for the API, optional per-app consent screen, client_credentials grant, docs. Everything the spec lists for those areas is out of scope here.

## Global Constraints

- Runtime Node.js >= 24; Docker base image `node:24-alpine`. ESM only; relative imports end in `.js`.
- Database Postgres 17. No Redis. All state (sessions, OIDC artifacts, rate limits) in Postgres.
- Env vars exactly: `AUTHI_ISSUER_URL`, `AUTHI_COOKIE_DOMAIN`, `AUTHI_SECRET_KEY` (32 bytes base64), `DATABASE_URL`, `AUTHI_BOOTSTRAP_ADMIN_USER`, `AUTHI_BOOTSTRAP_ADMIN_PASSWORD`, `AUTHI_BOOTSTRAP_ADMIN_EMAIL`, `AUTHI_TRUST_PROXY`, `PORT` (default 9000), `LOG_LEVEL`.
- OIDC issuer = `AUTHI_ISSUER_URL` + `/oidc`. Scopes: `openid`, `offline_access`, `profile`, `email`, `groups`. Claims: `sub`, `name`, `given_name`, `family_name`, `preferred_username`, `email`, `email_verified`, `groups` (array of group names). Flow: authorization code (PKCE required for public clients, allowed for all), refresh token. No implicit.
- Session cookie `authi_session`: HttpOnly, SameSite=Lax, Secure when issuer is https, Domain = `AUTHI_COOKIE_DOMAIN` when set, absolute lifetime 12h.
- Forward-auth endpoint `GET /outpost/auth`; response headers `X-Authi-User`, `X-Authi-Email`, `X-Authi-Name`, `X-Authi-Groups`, `X-Authi-Uid`. `X-Authi-Name` and each group name in `X-Authi-Groups` are `encodeURIComponent`-encoded (groups joined with `,`).
- Secrets at rest: AES-256-GCM with HKDF-derived per-purpose keys from `AUTHI_SECRET_KEY`. Passwords argon2id. API tokens and session tokens stored only as SHA-256 hex.
- Admin REST API under `/api/v1`, Bearer API tokens only (cookie auth comes in plan 4), errors as `application/problem+json` (RFC 7807).
- Passwords: minimum 12 characters. Usernames: `^[a-zA-Z0-9._@-]{2,64}$`. App slugs (= OIDC `client_id`): `^[a-z0-9][a-z0-9-]{1,62}$`.
- Deactivation never deletes data. Deleting a group removes it from every application's `allowed_group_ids`.

## Review Focus

1. Open redirects via `rd` (`//evil.com`, `/\evil.com`, `/%09/evil.com`-style control chars, `https://example.com.evil.com`, `javascript:`) must fall back to `/` — pinned in Task 7.
2. A deactivated user, or one removed from an app's allowed groups, must lose access immediately: session invalid, forward-auth redirects/403s, refresh token grant fails — pinned in Tasks 6, 12, 13.
3. Signing in with a different-case username or with the email address must work, and rate limiting must not be bypassable by changing case — pinned in Task 6.
4. Non-ASCII display names and group names containing commas must not crash forward-auth header writing — pinned in Task 13.
5. Restarting the container must be idempotent: migrations run once (also under concurrent starts), signing keys are not regenerated, the bootstrap admin is not recreated or its password reset — pinned in Tasks 3, 11, 14.

## File Structure

```
package.json, tsconfig.json, tsconfig.build.json, vitest.config.ts, .gitignore
docker-compose.test.yml            Postgres for tests (port 55432)
Dockerfile, .dockerignore, docker-compose.yml, .env.example, README.md
migrations/001_core.sql            all plan-1 tables
views/layout.eta, login.eta, home.eta, error.eta
src/
  config.ts                        env → Config (zod)
  errors.ts                        AppError hierarchy + pg error helpers
  util.ts                          isUuid, escapeLike
  crypto/secrets.ts                SecretBox (AES-GCM), deriveKey, randomToken, hashToken
  crypto/passwords.ts              argon2id hash/verify (constant-ish time on unknown user)
  db/schema.ts                     Kysely table types
  db/db.ts                         createDb
  db/migrate.ts                    SQL-file migrator with advisory lock
  events/bus.ts                    typed in-process EventBus
  audit/audit.ts                   AuditLog (record/list)
  identity/users.ts                UserService
  identity/groups.ts               GroupService
  auth/sessions.ts                 SessionService + SESSION_COOKIE
  auth/rate-limit.ts               LoginRateLimiter
  auth/local-login.ts              LocalAuthenticator
  auth/redirects.ts                isSafeRedirect / safeRedirectTarget
  apps/policy.ts                   canAccess
  apps/applications.ts             ApplicationService
  api/tokens.ts                    ApiTokenService
  api/plugin.ts                    /api/v1 auth hook + route registration
  api/users.ts, api/groups.ts, api/applications.ts, api/api-tokens.ts, api/audit.ts, api/keys.ts
  oidc/keys.ts                     SigningKeyService
  oidc/adapter.ts                  PostgresAdapter + purgeExpiredOidcPayloads
  oidc/provider.ts                 createOidcProvider
  oidc/holder.ts                   OidcProviderHolder (reloadable)
  http/app.ts                      buildApp
  http/views.ts                    renderPage
  http/csrf.ts                     double-submit CSRF
  http/context.ts                  currentUser, sessionCookieOptions, redirectRules
  http/login-routes.ts             /login, /logout, /
  http/interaction-routes.ts       /interaction/:uid
  forward-auth/routes.ts           /outpost/auth
  services.ts                      createServices, startServices
  bootstrap.ts                     ensureBootstrapAdmin
  maintenance.ts                   runMaintenanceOnce, startMaintenance
  cli/commands.ts                  runCommand
  cli.ts                           CLI entry
  server.ts                        process entry
tests/
  helpers/db.ts, helpers/app.ts, helpers/browser.ts, helpers/net.ts
  (one test file per module, paths given per task)
```

## Prerequisites (once, before Task 1)

Docker must be running. Tests need the test database: after Task 3 creates `docker-compose.test.yml`, run `npm run db:test:up` before `npm test`. Every DB-backed test creates and drops its own database, so tests can run in parallel.

---
### Task 1: Project scaffold and configuration

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`, `.gitignore`
- Create: `src/config.ts`
- Test: `tests/config.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```ts
  export interface Config {
    issuerUrl: string;            // no trailing slash
    cookieDomain: string | undefined;
    secureCookies: boolean;       // issuerUrl is https
    secretKey: Buffer;            // 32 bytes
    databaseUrl: string;
    bootstrapAdmin: { username: string; password: string; email?: string } | undefined;
    trustProxy: string;           // passed to Fastify trustProxy
    port: number;
    logLevel: string;
  }
  export function loadConfig(env?: Record<string, string | undefined>): Config;
  ```

- [ ] **Step 1: Scaffold the package**

```bash
npm init -y
npm pkg set name=authi version=0.1.0 private=true type=module engines.node=">=24"
npm pkg set scripts.dev="tsx watch src/server.ts" scripts.build="tsc -p tsconfig.build.json" scripts.start="node dist/server.js" scripts.cli="tsx src/cli.ts" scripts.test="vitest run" scripts.typecheck="tsc --noEmit" scripts.db:test:up="docker compose -f docker-compose.test.yml up -d --wait" scripts.db:test:down="docker compose -f docker-compose.test.yml down"
npm pkg delete main scripts.test-placeholder keywords author license description
npm i fastify @fastify/cookie @fastify/formbody @fastify/middie oidc-provider kysely pg argon2 zod eta
npm i -D typescript@~5.9 tsx vitest @types/node@^24 @types/pg @types/oidc-provider openid-client
```

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2023",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": ".",
    "types": ["node"]
  },
  "include": ["src", "tests", "vitest.config.ts"]
}
```

`tsconfig.build.json`:
```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": { "rootDir": "src", "outDir": "dist" },
  "include": ["src"]
}
```

`vitest.config.ts`:
```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
```

`.gitignore`:
```
node_modules/
dist/
coverage/
.env
```

- [ ] **Step 2: Write the failing test** — `tests/config.test.ts`

```ts
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

const key = Buffer.alloc(32, 7).toString('base64');
const base = {
  AUTHI_ISSUER_URL: 'https://auth.example.com/',
  AUTHI_SECRET_KEY: key,
  DATABASE_URL: 'postgres://authi:authi@db/authi',
};

describe('loadConfig', () => {
  it('parses a minimal environment and applies defaults', () => {
    const c = loadConfig(base);
    expect(c.issuerUrl).toBe('https://auth.example.com');
    expect(c.secureCookies).toBe(true);
    expect(c.port).toBe(9000);
    expect(c.secretKey).toHaveLength(32);
    expect(c.cookieDomain).toBeUndefined();
    expect(c.bootstrapAdmin).toBeUndefined();
    expect(c.trustProxy).toBe('loopback,linklocal,uniquelocal');
  });

  it('treats empty strings as unset', () => {
    const c = loadConfig({ ...base, AUTHI_COOKIE_DOMAIN: '', AUTHI_BOOTSTRAP_ADMIN_USER: '' });
    expect(c.cookieDomain).toBeUndefined();
    expect(c.bootstrapAdmin).toBeUndefined();
  });

  it('rejects a secret key that is not 32 bytes', () => {
    expect(() => loadConfig({ ...base, AUTHI_SECRET_KEY: 'c2hvcnQ=' })).toThrow(/AUTHI_SECRET_KEY/);
  });

  it('requires a bootstrap password when a bootstrap user is set', () => {
    expect(() => loadConfig({ ...base, AUTHI_BOOTSTRAP_ADMIN_USER: 'admin' })).toThrow(
      /AUTHI_BOOTSTRAP_ADMIN_PASSWORD/,
    );
  });

  it('builds the bootstrap admin', () => {
    const c = loadConfig({
      ...base,
      AUTHI_BOOTSTRAP_ADMIN_USER: 'admin',
      AUTHI_BOOTSTRAP_ADMIN_PASSWORD: 'correct-horse-battery',
      AUTHI_BOOTSTRAP_ADMIN_EMAIL: 'admin@example.com',
    });
    expect(c.bootstrapAdmin).toEqual({
      username: 'admin',
      password: 'correct-horse-battery',
      email: 'admin@example.com',
    });
  });

  it('uses insecure cookies for an http issuer', () => {
    expect(loadConfig({ ...base, AUTHI_ISSUER_URL: 'http://localhost:9000' }).secureCookies).toBe(false);
  });

  it('rejects non-http issuer URLs', () => {
    expect(() => loadConfig({ ...base, AUTHI_ISSUER_URL: 'ftp://auth.example.com' })).toThrow(/AUTHI_ISSUER_URL/);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/config.test.ts`
Expected: FAIL — cannot find module `../src/config.js`.

- [ ] **Step 4: Implement** — `src/config.ts`

```ts
import { z } from 'zod';

const envSchema = z
  .object({
    AUTHI_ISSUER_URL: z.url({ protocol: /^https?$/ }),
    AUTHI_COOKIE_DOMAIN: z.string().min(1).optional(),
    AUTHI_SECRET_KEY: z.string().refine((v) => Buffer.from(v, 'base64').length === 32, {
      message: 'must be 32 random bytes, base64-encoded (openssl rand -base64 32)',
    }),
    DATABASE_URL: z.string().min(1),
    AUTHI_BOOTSTRAP_ADMIN_USER: z.string().min(1).optional(),
    AUTHI_BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),
    AUTHI_BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
    AUTHI_TRUST_PROXY: z.string().default('loopback,linklocal,uniquelocal'),
    PORT: z.coerce.number().int().positive().default(9000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  })
  .superRefine((env, ctx) => {
    if (env.AUTHI_BOOTSTRAP_ADMIN_USER && !env.AUTHI_BOOTSTRAP_ADMIN_PASSWORD) {
      ctx.addIssue({
        code: 'custom',
        path: ['AUTHI_BOOTSTRAP_ADMIN_PASSWORD'],
        message: 'required when AUTHI_BOOTSTRAP_ADMIN_USER is set',
      });
    }
  });

export interface Config {
  issuerUrl: string;
  cookieDomain: string | undefined;
  secureCookies: boolean;
  secretKey: Buffer;
  databaseUrl: string;
  bootstrapAdmin: { username: string; password: string; email?: string } | undefined;
  trustProxy: string;
  port: number;
  logLevel: string;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const present = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== ''));
  const parsed = envSchema.safeParse(present);
  if (!parsed.success) {
    throw new Error(`Invalid configuration:\n${z.prettifyError(parsed.error)}`);
  }
  const e = parsed.data;
  const issuerUrl = e.AUTHI_ISSUER_URL.replace(/\/+$/, '');
  return {
    issuerUrl,
    cookieDomain: e.AUTHI_COOKIE_DOMAIN,
    secureCookies: issuerUrl.startsWith('https://'),
    secretKey: Buffer.from(e.AUTHI_SECRET_KEY, 'base64'),
    databaseUrl: e.DATABASE_URL,
    bootstrapAdmin: e.AUTHI_BOOTSTRAP_ADMIN_USER
      ? {
          username: e.AUTHI_BOOTSTRAP_ADMIN_USER,
          password: e.AUTHI_BOOTSTRAP_ADMIN_PASSWORD!,
          ...(e.AUTHI_BOOTSTRAP_ADMIN_EMAIL ? { email: e.AUTHI_BOOTSTRAP_ADMIN_EMAIL } : {}),
        }
      : undefined,
    trustProxy: e.AUTHI_TRUST_PROXY,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
  };
}
```

- [ ] **Step 5: Run tests and typecheck**

Run: `npx vitest run tests/config.test.ts && npm run typecheck`
Expected: 7 tests PASS, no type errors.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json tsconfig.json tsconfig.build.json vitest.config.ts .gitignore src/config.ts tests/config.test.ts
git commit -m "feat: scaffold project and env configuration"
```

---

### Task 2: Crypto primitives

**Files:**
- Create: `src/crypto/secrets.ts`, `src/crypto/passwords.ts`
- Test: `tests/crypto.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```ts
  // secrets.ts
  export interface SecretBox { encrypt(plain: string): string; decrypt(box: string): string }
  export function deriveKey(master: Buffer, purpose: string): Buffer;   // 32 bytes, HKDF-SHA256
  export function createSecretBox(master: Buffer): SecretBox;
  export function randomToken(bytes?: number): string;                 // base64url, default 32 bytes
  export function hashToken(token: string): string;                    // sha256 hex
  // passwords.ts
  export function hashPassword(password: string): Promise<string>;
  export function verifyPassword(hash: string | null, password: string): Promise<boolean>;
  ```

- [ ] **Step 1: Write the failing test** — `tests/crypto.test.ts`

```ts
import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../src/crypto/passwords.js';
import { createSecretBox, deriveKey, hashToken, randomToken } from '../src/crypto/secrets.js';

const master = Buffer.alloc(32, 3);

describe('SecretBox', () => {
  const box = createSecretBox(master);

  it('round-trips text, including empty strings and unicode', () => {
    for (const plain of ['hunter2', '', 'zoë 🔐']) {
      expect(box.decrypt(box.encrypt(plain))).toBe(plain);
    }
  });

  it('produces a different ciphertext each time', () => {
    expect(box.encrypt('same')).not.toBe(box.encrypt('same'));
  });

  it('rejects tampered ciphertext', () => {
    const sealed = box.encrypt('secret');
    const parts = sealed.split('.');
    parts[2] = Buffer.from('tampered').toString('base64url');
    expect(() => box.decrypt(parts.join('.'))).toThrow();
  });

  it('rejects ciphertext from another key', () => {
    const other = createSecretBox(Buffer.alloc(32, 4));
    expect(() => other.decrypt(box.encrypt('secret'))).toThrow();
  });

  it('rejects malformed input', () => {
    expect(() => box.decrypt('nonsense')).toThrow(/Malformed/);
  });
});

describe('deriveKey', () => {
  it('derives distinct 32-byte keys per purpose', () => {
    const a = deriveKey(master, 'a');
    expect(a).toHaveLength(32);
    expect(a.equals(deriveKey(master, 'a'))).toBe(true);
    expect(a.equals(deriveKey(master, 'b'))).toBe(false);
  });
});

describe('tokens', () => {
  it('generates unique url-safe tokens', () => {
    const t = randomToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken()).not.toBe(t);
  });

  it('hashes tokens deterministically to hex', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('passwords', () => {
  it('hashes with argon2id and verifies', async () => {
    const hash = await hashPassword('correct-horse-battery');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'correct-horse-battery')).toBe(true);
    expect(await verifyPassword(hash, 'wrong-password-123')).toBe(false);
  });

  it('returns false for a missing hash', async () => {
    expect(await verifyPassword(null, 'anything')).toBe(false);
  });

  it('returns false for a garbage hash instead of throwing', async () => {
    expect(await verifyPassword('not-a-hash', 'anything')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement** — `src/crypto/secrets.ts`

```ts
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';

export interface SecretBox {
  encrypt(plain: string): string;
  decrypt(box: string): string;
}

export function deriveKey(master: Buffer, purpose: string): Buffer {
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), `authi:${purpose}`, 32));
}

export function createSecretBox(master: Buffer): SecretBox {
  const key = deriveKey(master, 'secret-box');
  return {
    encrypt(plain) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
      return ['v1', iv, ciphertext, cipher.getAuthTag()]
        .map((part) => (typeof part === 'string' ? part : part.toString('base64url')))
        .join('.');
    },
    decrypt(box) {
      const [version, iv, ciphertext, tag, ...rest] = box.split('.');
      if (version !== 'v1' || iv === undefined || ciphertext === undefined || tag === undefined || rest.length) {
        throw new Error('Malformed secret box');
      }
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]).toString('utf8');
    },
  };
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
```

`src/crypto/passwords.ts`:
```ts
import * as argon2 from 'argon2';

// OWASP baseline for argon2id: m=19 MiB, t=2, p=1.
const OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

let dummyHash: Promise<string> | undefined;

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, OPTIONS);
}

export async function verifyPassword(hash: string | null, password: string): Promise<boolean> {
  if (hash === null) {
    // Spend the same work as a real check so unknown usernames are not distinguishable by timing.
    dummyHash ??= argon2.hash('authi-dummy-password', OPTIONS);
    await argon2.verify(await dummyHash, password);
    return false;
  }
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/crypto.test.ts && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto tests/crypto.test.ts
git commit -m "feat: add secret box, token hashing and argon2id passwords"
```

---

### Task 3: Database, schema and migrator

**Files:**
- Create: `docker-compose.test.yml`, `migrations/001_core.sql`, `src/db/schema.ts`, `src/db/db.ts`, `src/db/migrate.ts`, `tests/helpers/db.ts`
- Test: `tests/db/migrate.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```ts
  // db.ts
  export type Db = Kysely<Database>;
  export function createDb(databaseUrl: string): Db;
  // migrate.ts
  export function runMigrations(db: Db): Promise<string[]>;   // names of newly applied files
  // tests/helpers/db.ts
  export interface TestDb { db: Db; url: string; destroy(): Promise<void> }
  export function createTestDb(): Promise<TestDb>;            // fresh migrated database
  ```
  Table/column names in `migrations/001_core.sql` and `src/db/schema.ts` below are the contract for all later tasks.

- [ ] **Step 1: Test database compose file** — `docker-compose.test.yml`

```yaml
services:
  postgres-test:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: authi
      POSTGRES_PASSWORD: authi
      POSTGRES_DB: postgres
    ports:
      - "55432:5432"
    tmpfs:
      - /var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authi"]
      interval: 2s
      timeout: 3s
      retries: 20
```

Run: `npm run db:test:up`
Expected: container `postgres-test` healthy.

- [ ] **Step 2: Write the failing test** — `tests/db/migrate.test.ts`

```ts
import { sql } from 'kysely';
import { afterEach, describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb | undefined;
afterEach(async () => {
  await t?.destroy();
  t = undefined;
});

describe('runMigrations', () => {
  it('creates all core tables', async () => {
    t = await createTestDb(); // runs migrations
    const { rows } = await sql<{ table_name: string }>`
      SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name
    `.execute(t.db);
    expect(rows.map((r) => r.table_name)).toEqual([
      'api_tokens',
      'applications',
      'audit_log',
      'group_members',
      'groups',
      'login_attempts',
      'oidc_payloads',
      'schema_migrations',
      'sessions',
      'signing_keys',
      'users',
    ]);
  });

  it('is a no-op the second time', async () => {
    t = await createTestDb();
    expect(await runMigrations(t.db)).toEqual([]);
  });

  it('applies each migration once under concurrent runs', async () => {
    t = await createTestDb();
    await sql`DELETE FROM schema_migrations`.execute(t.db);
    await sql`DROP TABLE users, groups, group_members, applications, sessions, oidc_payloads, signing_keys, api_tokens, audit_log, login_attempts CASCADE`.execute(t.db);
    const results = await Promise.all([runMigrations(t.db), runMigrations(t.db), runMigrations(t.db)]);
    expect(results.flat()).toEqual(['001_core.sql']);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/db/migrate.test.ts`
Expected: FAIL — helper/migrator modules not found.

- [ ] **Step 4: Migration** — `migrations/001_core.sql`

```sql
CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username        text NOT NULL,
  email           text,
  display_name    text NOT NULL DEFAULT '',
  given_name      text,
  family_name     text,
  is_active       boolean NOT NULL DEFAULT true,
  is_admin        boolean NOT NULL DEFAULT false,
  password_hash   text,
  totp_secret_enc text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));
CREATE UNIQUE INDEX users_email_key ON users (lower(email)) WHERE email IS NOT NULL;

CREATE TABLE groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  source_id   uuid,
  external_id text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_name_key ON groups (lower(name));

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE applications (
  id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug                       text NOT NULL UNIQUE,
  name                       text NOT NULL,
  oidc_enabled               boolean NOT NULL DEFAULT false,
  forward_auth_enabled       boolean NOT NULL DEFAULT false,
  client_id                  text NOT NULL UNIQUE,
  client_secret_enc          text NOT NULL,
  token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post')),
  redirect_uris              text[] NOT NULL DEFAULT '{}',
  post_logout_redirect_uris  text[] NOT NULL DEFAULT '{}',
  external_host              text,
  allowed_group_ids          uuid[] NOT NULL DEFAULT '{}',
  launch_url                 text,
  created_at                 timestamptz NOT NULL DEFAULT now(),
  updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX applications_external_host_key ON applications (lower(external_host)) WHERE external_host IS NOT NULL;

CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash   text NOT NULL UNIQUE,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  ip           text,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE oidc_payloads (
  id          text NOT NULL,
  type        text NOT NULL,
  payload     jsonb NOT NULL,
  grant_id    text,
  user_code   text,
  uid         text,
  expires_at  timestamptz,
  consumed_at timestamptz,
  PRIMARY KEY (type, id)
);
CREATE INDEX oidc_payloads_grant_idx ON oidc_payloads (grant_id);
CREATE INDEX oidc_payloads_uid_idx ON oidc_payloads (uid);
CREATE INDEX oidc_payloads_user_code_idx ON oidc_payloads (user_code);
CREATE INDEX oidc_payloads_expires_idx ON oidc_payloads (expires_at);

CREATE TABLE signing_keys (
  kid             text PRIMARY KEY,
  alg             text NOT NULL,
  private_jwk_enc text NOT NULL,
  status          text NOT NULL CHECK (status IN ('active', 'retired')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  retired_at      timestamptz
);

CREATE TABLE api_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  token_hash   text NOT NULL UNIQUE,
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at   timestamptz
);

CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor_type text NOT NULL,
  actor_id   text,
  action     text NOT NULL,
  target     text,
  details    jsonb NOT NULL DEFAULT '{}',
  ip         text
);
CREATE INDEX audit_log_at_idx ON audit_log (at);

CREATE TABLE login_attempts (
  id  bigserial PRIMARY KEY,
  key text NOT NULL,
  at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_key_at_idx ON login_attempts (key, at);
```

- [ ] **Step 5: Kysely types** — `src/db/schema.ts`

```ts
import type { ColumnType, Generated } from 'kysely';

/** jsonb columns: read as objects, always written as JSON strings. */
type Json<T = Record<string, unknown>> = ColumnType<T, string, string>;

export interface UsersTable {
  id: Generated<string>;
  username: string;
  email: string | null;
  display_name: Generated<string>;
  given_name: string | null;
  family_name: string | null;
  is_active: Generated<boolean>;
  is_admin: Generated<boolean>;
  password_hash: string | null;
  totp_secret_enc: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface GroupsTable {
  id: Generated<string>;
  name: string;
  description: Generated<string>;
  source_id: string | null;
  external_id: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface GroupMembersTable {
  group_id: string;
  user_id: string;
}

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post';

export interface ApplicationsTable {
  id: Generated<string>;
  slug: string;
  name: string;
  oidc_enabled: Generated<boolean>;
  forward_auth_enabled: Generated<boolean>;
  client_id: string;
  client_secret_enc: string;
  token_endpoint_auth_method: Generated<TokenEndpointAuthMethod>;
  redirect_uris: Generated<string[]>;
  post_logout_redirect_uris: Generated<string[]>;
  external_host: string | null;
  allowed_group_ids: Generated<string[]>;
  launch_url: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface SessionsTable {
  id: Generated<string>;
  token_hash: string;
  user_id: string;
  created_at: Generated<Date>;
  expires_at: Date;
  last_seen_at: Generated<Date>;
  ip: string | null;
  user_agent: string | null;
}

export interface OidcPayloadsTable {
  id: string;
  type: string;
  payload: Json;
  grant_id: string | null;
  user_code: string | null;
  uid: string | null;
  expires_at: Date | null;
  consumed_at: Date | null;
}

export interface SigningKeysTable {
  kid: string;
  alg: string;
  private_jwk_enc: string;
  status: 'active' | 'retired';
  created_at: Generated<Date>;
  retired_at: Date | null;
}

export interface ApiTokensTable {
  id: Generated<string>;
  name: string;
  token_hash: string;
  created_by: string | null;
  created_at: Generated<Date>;
  last_used_at: Date | null;
  expires_at: Date | null;
}

export interface AuditLogTable {
  id: Generated<string>;
  at: Generated<Date>;
  actor_type: string;
  actor_id: string | null;
  action: string;
  target: string | null;
  details: ColumnType<Record<string, unknown>, string | undefined, string>;
  ip: string | null;
}

export interface LoginAttemptsTable {
  id: Generated<string>;
  key: string;
  at: Generated<Date>;
}

export interface SchemaMigrationsTable {
  name: string;
  applied_at: Generated<Date>;
}

export interface Database {
  users: UsersTable;
  groups: GroupsTable;
  group_members: GroupMembersTable;
  applications: ApplicationsTable;
  sessions: SessionsTable;
  oidc_payloads: OidcPayloadsTable;
  signing_keys: SigningKeysTable;
  api_tokens: ApiTokensTable;
  audit_log: AuditLogTable;
  login_attempts: LoginAttemptsTable;
  schema_migrations: SchemaMigrationsTable;
}
```

- [ ] **Step 6: DB factory and migrator** — `src/db/db.ts`

```ts
import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import type { Database } from './schema.js';

export type Db = Kysely<Database>;

export function createDb(databaseUrl: string): Db {
  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString: databaseUrl, max: 10 }) }),
  });
}
```

`src/db/migrate.ts`:
```ts
import { readdir, readFile } from 'node:fs/promises';
import { sql } from 'kysely';
import type { Db } from './db.js';

// Resolves to <project>/migrations from both src/db (tsx) and dist/db (compiled).
const MIGRATIONS_DIR = new URL('../../migrations/', import.meta.url);
const LOCK_ID = 7_424_242; // arbitrary, unique to Auth.i

export async function runMigrations(db: Db): Promise<string[]> {
  return db.connection().execute(async (conn) => {
    await sql`SELECT pg_advisory_lock(${LOCK_ID})`.execute(conn);
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          name text PRIMARY KEY,
          applied_at timestamptz NOT NULL DEFAULT now()
        )
      `.execute(conn);
      const applied = new Set(
        (await conn.selectFrom('schema_migrations').select('name').execute()).map((r) => r.name),
      );
      const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort();
      const ran: string[] = [];
      for (const file of files) {
        if (applied.has(file)) continue;
        const text = await readFile(new URL(file, MIGRATIONS_DIR), 'utf8');
        await conn.transaction().execute(async (trx) => {
          await sql.raw(text).execute(trx);
          await trx.insertInto('schema_migrations').values({ name: file }).execute();
        });
        ran.push(file);
      }
      return ran;
    } finally {
      await sql`SELECT pg_advisory_unlock(${LOCK_ID})`.execute(conn);
    }
  });
}
```

- [ ] **Step 7: Test helper** — `tests/helpers/db.ts`

```ts
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDb, type Db } from '../../src/db/db.js';
import { runMigrations } from '../../src/db/migrate.js';

const ADMIN_URL = process.env.TEST_DATABASE_URL ?? 'postgres://authi:authi@localhost:55432/postgres';

export interface TestDb {
  db: Db;
  url: string;
  destroy(): Promise<void>;
}

async function admin(query: string): Promise<void> {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  try {
    await client.query(query);
  } finally {
    await client.end();
  }
}

export async function createTestDb(): Promise<TestDb> {
  const name = `authi_test_${randomBytes(6).toString('hex')}`;
  await admin(`CREATE DATABASE ${name}`);
  const url = new URL(ADMIN_URL);
  url.pathname = `/${name}`;
  const db = createDb(url.toString());
  await runMigrations(db);
  return {
    db,
    url: url.toString(),
    async destroy() {
      await db.destroy();
      await admin(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    },
  };
}
```

- [ ] **Step 8: Run tests**

Run: `npx vitest run tests/db/migrate.test.ts && npm run typecheck`
Expected: 3 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add docker-compose.test.yml migrations src/db tests/helpers/db.ts tests/db
git commit -m "feat: add postgres schema, kysely types and locked migrator"
```

---

### Task 4: Errors, utilities, event bus and audit log

**Files:**
- Create: `src/errors.ts`, `src/util.ts`, `src/events/bus.ts`, `src/audit/audit.ts`
- Test: `tests/events.test.ts`, `tests/audit.test.ts`, `tests/util.test.ts`

**Interfaces:**
- Consumes: `Db`, `createTestDb` (Task 3).
- Produces:
  ```ts
  // errors.ts
  export class AppError extends Error { readonly status: number; readonly title: string }
  export class NotFoundError extends AppError {}      // 404
  export class ConflictError extends AppError {}      // 409
  export class ValidationError extends AppError {}    // 400
  export class UnauthorizedError extends AppError {}  // 401
  export function isUniqueViolation(err: unknown): boolean;
  export function isForeignKeyViolation(err: unknown): boolean;
  // util.ts
  export function isUuid(value: string): boolean;
  export function escapeLike(value: string): string;
  // events/bus.ts
  export type DomainEvent = { type: 'user.created' | 'user.updated' | 'user.deactivated' | 'user.deleted'; userId: string }
    | { type: 'group.created' | 'group.updated'; groupId: string }
    | { type: 'group.deleted'; groupId: string; name: string }
    | { type: 'group.members_changed'; groupId: string; userIds: string[] };
  export class EventBus { constructor(onError?: (err: unknown, event: DomainEvent) => void); subscribe(h): () => void; publish(e): Promise<void> }
  // audit/audit.ts
  export type Actor = { type: 'user' | 'token'; id: string } | { type: 'system' } | { type: 'anonymous' };
  export interface AuditEntry { id: string; at: Date; actorType: string; actorId: string | null; action: string; target: string | null; details: Record<string, unknown>; ip: string | null }
  export class AuditLog { constructor(db: Db); record(e: { actor: Actor; action: string; target?: string | null; details?: Record<string, unknown>; ip?: string | null }): Promise<void>; list(opts?: { limit?: number; before?: string }): Promise<AuditEntry[]> }
  ```

- [ ] **Step 1: Write the failing tests**

`tests/util.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { escapeLike, isUuid } from '../src/util.js';

describe('util', () => {
  it('recognises uuids', () => {
    expect(isUuid('8d0f1d8e-4c55-4b5e-9a35-1f0b2c3d4e5f')).toBe(true);
    expect(isUuid('nope')).toBe(false);
    expect(isUuid("8d0f1d8e-4c55-4b5e-9a35-1f0b2c3d4e5f' OR 1=1")).toBe(false);
  });

  it('escapes LIKE wildcards', () => {
    expect(escapeLike('50%_off\\')).toBe('50\\%\\_off\\\\');
  });
});
```

`tests/events.test.ts`:
```ts
import { describe, expect, it, vi } from 'vitest';
import { EventBus, type DomainEvent } from '../src/events/bus.js';

describe('EventBus', () => {
  it('delivers events to subscribers in order', async () => {
    const bus = new EventBus();
    const seen: string[] = [];
    bus.subscribe((e) => {
      seen.push(`a:${e.type}`);
    });
    bus.subscribe(async (e) => {
      seen.push(`b:${e.type}`);
    });
    await bus.publish({ type: 'user.created', userId: 'u1' });
    expect(seen).toEqual(['a:user.created', 'b:user.created']);
  });

  it('isolates failing handlers and reports them', async () => {
    const onError = vi.fn();
    const bus = new EventBus(onError);
    const seen: DomainEvent[] = [];
    bus.subscribe(() => {
      throw new Error('boom');
    });
    bus.subscribe((e) => {
      seen.push(e);
    });
    const event: DomainEvent = { type: 'group.created', groupId: 'g1' };
    await bus.publish(event);
    expect(seen).toEqual([event]);
    expect(onError).toHaveBeenCalledWith(expect.any(Error), event);
  });

  it('supports unsubscribe', async () => {
    const bus = new EventBus();
    const handler = vi.fn();
    const off = bus.subscribe(handler);
    off();
    await bus.publish({ type: 'user.deleted', userId: 'u1' });
    expect(handler).not.toHaveBeenCalled();
  });
});
```

`tests/audit.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit/audit.js';
import { createTestDb, type TestDb } from './helpers/db.js';

let t: TestDb;
let audit: AuditLog;
beforeEach(async () => {
  t = await createTestDb();
  audit = new AuditLog(t.db);
});
afterEach(() => t.destroy());

describe('AuditLog', () => {
  it('records entries and lists newest first', async () => {
    await audit.record({ actor: { type: 'system' }, action: 'first' });
    await audit.record({
      actor: { type: 'user', id: 'u1' },
      action: 'second',
      target: 'thing',
      details: { a: 1 },
      ip: '10.0.0.1',
    });
    const entries = await audit.list();
    expect(entries.map((e) => e.action)).toEqual(['second', 'first']);
    expect(entries[0]).toMatchObject({
      actorType: 'user',
      actorId: 'u1',
      target: 'thing',
      details: { a: 1 },
      ip: '10.0.0.1',
    });
    expect(entries[1]).toMatchObject({ actorType: 'system', actorId: null, details: {} });
  });

  it('paginates with before and limit', async () => {
    for (const action of ['a', 'b', 'c']) await audit.record({ actor: { type: 'system' }, action });
    const [newest] = await audit.list({ limit: 1 });
    expect(newest!.action).toBe('c');
    const older = await audit.list({ before: newest!.id });
    expect(older.map((e) => e.action)).toEqual(['b', 'a']);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/util.test.ts tests/events.test.ts tests/audit.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement**

`src/errors.ts`:
```ts
export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    message?: string,
  ) {
    super(message ?? title);
    this.name = new.target.name;
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'The requested resource does not exist') {
    super(404, 'Not Found', message);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'The resource already exists') {
    super(409, 'Conflict', message);
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super(400, 'Bad Request', message);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'A valid API token is required') {
    super(401, 'Unauthorized', message);
  }
}

function pgCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : undefined;
}

export const isUniqueViolation = (err: unknown): boolean => pgCode(err) === '23505';
export const isForeignKeyViolation = (err: unknown): boolean => pgCode(err) === '23503';
```

`src/util.ts`:
```ts
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** Escapes %, _ and \ for use inside a LIKE/ILIKE pattern (default escape char is \). */
export function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (c) => `\\${c}`);
}
```

`src/events/bus.ts`:
```ts
export type DomainEvent =
  | { type: 'user.created' | 'user.updated' | 'user.deactivated' | 'user.deleted'; userId: string }
  | { type: 'group.created' | 'group.updated'; groupId: string }
  | { type: 'group.deleted'; groupId: string; name: string }
  | { type: 'group.members_changed'; groupId: string; userIds: string[] };

export type EventHandler = (event: DomainEvent) => void | Promise<void>;

export class EventBus {
  readonly #handlers = new Set<EventHandler>();

  constructor(private readonly onError: (err: unknown, event: DomainEvent) => void = () => {}) {}

  subscribe(handler: EventHandler): () => void {
    this.#handlers.add(handler);
    return () => this.#handlers.delete(handler);
  }

  async publish(event: DomainEvent): Promise<void> {
    for (const handler of this.#handlers) {
      try {
        await handler(event);
      } catch (err) {
        this.onError(err, event);
      }
    }
  }
}
```

`src/audit/audit.ts`:
```ts
import type { Db } from '../db/db.js';

export type Actor = { type: 'user' | 'token'; id: string } | { type: 'system' } | { type: 'anonymous' };

export interface AuditEntry {
  id: string;
  at: Date;
  actorType: string;
  actorId: string | null;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
  ip: string | null;
}

export interface AuditRecordInput {
  actor: Actor;
  action: string;
  target?: string | null;
  details?: Record<string, unknown>;
  ip?: string | null;
}

export class AuditLog {
  constructor(private readonly db: Db) {}

  async record(input: AuditRecordInput): Promise<void> {
    await this.db
      .insertInto('audit_log')
      .values({
        actor_type: input.actor.type,
        actor_id: 'id' in input.actor ? input.actor.id : null,
        action: input.action,
        target: input.target ?? null,
        details: JSON.stringify(input.details ?? {}),
        ip: input.ip ?? null,
      })
      .execute();
  }

  async list(opts: { limit?: number; before?: string } = {}): Promise<AuditEntry[]> {
    let query = this.db
      .selectFrom('audit_log')
      .selectAll()
      .orderBy('id', 'desc')
      .limit(opts.limit ?? 100);
    if (opts.before) query = query.where('id', '<', opts.before);
    const rows = await query.execute();
    return rows.map((r) => ({
      id: r.id,
      at: r.at,
      actorType: r.actor_type,
      actorId: r.actor_id,
      action: r.action,
      target: r.target,
      details: r.details,
      ip: r.ip,
    }));
  }
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/util.test.ts tests/events.test.ts tests/audit.test.ts && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts src/util.ts src/events src/audit tests/util.test.ts tests/events.test.ts tests/audit.test.ts
git commit -m "feat: add error types, event bus and audit log"
```

---
### Task 5: Users and groups

**Files:**
- Create: `src/identity/users.ts`, `src/identity/groups.ts`
- Test: `tests/identity/users.test.ts`, `tests/identity/groups.test.ts`

**Interfaces:**
- Consumes: `Db`, `EventBus`, `DomainEvent`, `hashPassword`, `ConflictError`, `NotFoundError`, `isUniqueViolation`, `isForeignKeyViolation`, `isUuid`, `escapeLike`.
- Produces:
  ```ts
  // users.ts
  export interface User { id: string; username: string; email: string | null; displayName: string; givenName: string | null;
    familyName: string | null; isActive: boolean; isAdmin: boolean; hasPassword: boolean; createdAt: Date; updatedAt: Date }
  export interface CreateUserInput { username: string; email?: string | null; displayName?: string; givenName?: string | null;
    familyName?: string | null; isAdmin?: boolean; isActive?: boolean; password?: string }
  export type UpdateUserInput = Partial<Omit<CreateUserInput, 'password'>>;
  export function toUser(row: Selectable<UsersTable>): User;
  export class UserService {
    constructor(db: Db, events: EventBus);
    create(input: CreateUserInput): Promise<User>;
    get(id: string): Promise<User | null>;
    findByLogin(identifier: string): Promise<{ user: User; passwordHash: string | null } | null>;
    list(opts?: { search?: string; limit?: number; offset?: number }): Promise<User[]>;
    count(): Promise<number>;
    update(id: string, input: UpdateUserInput): Promise<User>;
    setPassword(id: string, password: string | null): Promise<void>;
    delete(id: string): Promise<void>;
    groupNames(userId: string): Promise<string[]>;
  }
  // groups.ts
  export interface Group { id: string; name: string; description: string; sourceId: string | null; createdAt: Date; updatedAt: Date }
  export class GroupService {
    constructor(db: Db, events: EventBus);
    create(input: { name: string; description?: string }): Promise<Group>;
    get(id: string): Promise<Group | null>;
    list(): Promise<Group[]>;
    update(id: string, input: { name?: string; description?: string }): Promise<Group>;
    delete(id: string): Promise<void>;
    listMembers(groupId: string): Promise<User[]>;
    addMember(groupId: string, userId: string): Promise<void>;
    removeMember(groupId: string, userId: string): Promise<void>;
    groupsForUser(userId: string): Promise<Group[]>;
    groupIdsForUser(userId: string): Promise<string[]>;
    countExisting(ids: string[]): Promise<number>;
  }
  ```

- [ ] **Step 1: Write the failing tests**

`tests/identity/users.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConflictError, NotFoundError } from '../../src/errors.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let events: DomainEvent[];

beforeEach(async () => {
  t = await createTestDb();
  const bus = new EventBus();
  events = [];
  bus.subscribe((e) => {
    events.push(e);
  });
  users = new UserService(t.db, bus);
});
afterEach(() => t.destroy());

describe('UserService', () => {
  it('creates a user with defaults and emits user.created', async () => {
    const u = await users.create({ username: 'alice', email: 'alice@example.com', password: 'correct-horse-battery' });
    expect(u).toMatchObject({
      username: 'alice',
      email: 'alice@example.com',
      displayName: 'alice',
      isActive: true,
      isAdmin: false,
      hasPassword: true,
    });
    expect(events).toEqual([{ type: 'user.created', userId: u.id }]);
  });

  it('rejects duplicate usernames and emails case-insensitively', async () => {
    await users.create({ username: 'alice', email: 'alice@example.com' });
    await expect(users.create({ username: 'ALICE' })).rejects.toBeInstanceOf(ConflictError);
    await expect(users.create({ username: 'bob', email: 'Alice@Example.com' })).rejects.toBeInstanceOf(ConflictError);
  });

  it('finds users by username or email in any case', async () => {
    const u = await users.create({ username: 'alice', email: 'alice@example.com', password: 'correct-horse-battery' });
    expect((await users.findByLogin('ALICE'))?.user.id).toBe(u.id);
    expect((await users.findByLogin('Alice@Example.COM'))?.user.id).toBe(u.id);
    expect((await users.findByLogin('alice'))?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(await users.findByLogin('nobody')).toBeNull();
  });

  it('returns null for unknown or malformed ids', async () => {
    expect(await users.get('00000000-0000-0000-0000-000000000000')).toBeNull();
    expect(await users.get('not-a-uuid')).toBeNull();
  });

  it('updates and emits user.updated, or user.deactivated on deactivation', async () => {
    const u = await users.create({ username: 'alice' });
    events.length = 0;
    const updated = await users.update(u.id, { displayName: 'Alice A.' });
    expect(updated.displayName).toBe('Alice A.');
    const deactivated = await users.update(u.id, { isActive: false });
    expect(deactivated.isActive).toBe(false);
    expect(events).toEqual([
      { type: 'user.updated', userId: u.id },
      { type: 'user.deactivated', userId: u.id },
    ]);
  });

  it('throws NotFoundError when updating a missing user', async () => {
    await expect(users.update('00000000-0000-0000-0000-000000000000', { displayName: 'x' })).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('maps unique violations on update to ConflictError', async () => {
    await users.create({ username: 'alice' });
    const bob = await users.create({ username: 'bob' });
    await expect(users.update(bob.id, { username: 'Alice' })).rejects.toBeInstanceOf(ConflictError);
  });

  it('lists with a search that treats wildcards literally', async () => {
    await users.create({ username: 'alice', displayName: 'Alice 100%' });
    await users.create({ username: 'bob' });
    expect((await users.list()).map((u) => u.username)).toEqual(['alice', 'bob']);
    expect((await users.list({ search: '100%' })).map((u) => u.username)).toEqual(['alice']);
    expect(await users.list({ search: '%' })).toHaveLength(1);
    expect(await users.count()).toBe(2);
  });

  it('sets and clears passwords', async () => {
    const u = await users.create({ username: 'alice' });
    await users.setPassword(u.id, 'correct-horse-battery');
    expect((await users.get(u.id))?.hasPassword).toBe(true);
    await users.setPassword(u.id, null);
    expect((await users.get(u.id))?.hasPassword).toBe(false);
  });

  it('deletes users and emits user.deleted', async () => {
    const u = await users.create({ username: 'alice' });
    await users.delete(u.id);
    expect(await users.get(u.id)).toBeNull();
    expect(events.at(-1)).toEqual({ type: 'user.deleted', userId: u.id });
    await expect(users.delete(u.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
```

`tests/identity/groups.test.ts`:
```ts
import { sql } from 'kysely';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConflictError, NotFoundError } from '../../src/errors.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { GroupService } from '../../src/identity/groups.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let groups: GroupService;
let events: DomainEvent[];

beforeEach(async () => {
  t = await createTestDb();
  const bus = new EventBus();
  events = [];
  bus.subscribe((e) => {
    events.push(e);
  });
  users = new UserService(t.db, bus);
  groups = new GroupService(t.db, bus);
});
afterEach(() => t.destroy());

describe('GroupService', () => {
  it('creates, lists and rejects duplicate names', async () => {
    const g = await groups.create({ name: 'Staff', description: 'Everyone' });
    expect(g).toMatchObject({ name: 'Staff', description: 'Everyone', sourceId: null });
    await expect(groups.create({ name: 'staff' })).rejects.toBeInstanceOf(ConflictError);
    expect((await groups.list()).map((x) => x.name)).toEqual(['Staff']);
    expect(events).toContainEqual({ type: 'group.created', groupId: g.id });
  });

  it('adds members idempotently and emits members_changed once', async () => {
    const g = await groups.create({ name: 'staff' });
    const u = await users.create({ username: 'alice' });
    events.length = 0;
    await groups.addMember(g.id, u.id);
    await groups.addMember(g.id, u.id);
    expect(events).toEqual([{ type: 'group.members_changed', groupId: g.id, userIds: [u.id] }]);
    expect((await groups.listMembers(g.id)).map((m) => m.username)).toEqual(['alice']);
    expect(await groups.groupIdsForUser(u.id)).toEqual([g.id]);
    expect(await users.groupNames(u.id)).toEqual(['staff']);
  });

  it('removes members', async () => {
    const g = await groups.create({ name: 'staff' });
    const u = await users.create({ username: 'alice' });
    await groups.addMember(g.id, u.id);
    events.length = 0;
    await groups.removeMember(g.id, u.id);
    await groups.removeMember(g.id, u.id);
    expect(events).toEqual([{ type: 'group.members_changed', groupId: g.id, userIds: [u.id] }]);
    expect(await groups.groupIdsForUser(u.id)).toEqual([]);
  });

  it('throws NotFoundError when adding an unknown user or group', async () => {
    const g = await groups.create({ name: 'staff' });
    await expect(groups.addMember(g.id, '00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(NotFoundError);
    await expect(groups.addMember('not-a-uuid', '00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('updates and deletes, removing the group from application allow-lists', async () => {
    const g = await groups.create({ name: 'staff' });
    await sql`
      INSERT INTO applications (slug, name, client_id, client_secret_enc, allowed_group_ids)
      VALUES ('demo', 'Demo', 'demo', 'x', ARRAY[${g.id}]::uuid[])
    `.execute(t.db);
    expect((await groups.update(g.id, { name: 'crew' })).name).toBe('crew');
    await groups.delete(g.id);
    expect(await groups.get(g.id)).toBeNull();
    const app = await t.db.selectFrom('applications').select('allowed_group_ids').executeTakeFirstOrThrow();
    expect(app.allowed_group_ids).toEqual([]);
    expect(events.at(-1)).toEqual({ type: 'group.deleted', groupId: g.id, name: 'crew' });
  });

  it('counts existing group ids', async () => {
    const g = await groups.create({ name: 'staff' });
    expect(await groups.countExisting([g.id, '00000000-0000-0000-0000-000000000000', 'junk'])).toBe(1);
    expect(await groups.countExisting([])).toBe(0);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/identity`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement** — `src/identity/users.ts`

```ts
import type { Selectable } from 'kysely';
import { hashPassword } from '../crypto/passwords.js';
import type { Db } from '../db/db.js';
import type { UsersTable } from '../db/schema.js';
import { ConflictError, NotFoundError, isUniqueViolation } from '../errors.js';
import type { EventBus } from '../events/bus.js';
import { escapeLike, isUuid } from '../util.js';

export interface User {
  id: string;
  username: string;
  email: string | null;
  displayName: string;
  givenName: string | null;
  familyName: string | null;
  isActive: boolean;
  isAdmin: boolean;
  hasPassword: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  username: string;
  email?: string | null;
  displayName?: string;
  givenName?: string | null;
  familyName?: string | null;
  isAdmin?: boolean;
  isActive?: boolean;
  password?: string;
}

export type UpdateUserInput = Partial<Omit<CreateUserInput, 'password'>>;

export function toUser(row: Selectable<UsersTable>): User {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    displayName: row.display_name,
    givenName: row.given_name,
    familyName: row.family_name,
    isActive: row.is_active,
    isAdmin: row.is_admin,
    hasPassword: row.password_hash !== null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'A user with this username or email already exists';

export class UserService {
  constructor(
    private readonly db: Db,
    private readonly events: EventBus,
  ) {}

  async create(input: CreateUserInput): Promise<User> {
    const passwordHash = input.password ? await hashPassword(input.password) : null;
    let row: Selectable<UsersTable>;
    try {
      row = await this.db
        .insertInto('users')
        .values({
          username: input.username,
          email: input.email ?? null,
          display_name: input.displayName ?? input.username,
          given_name: input.givenName ?? null,
          family_name: input.familyName ?? null,
          is_admin: input.isAdmin ?? false,
          is_active: input.isActive ?? true,
          password_hash: passwordHash,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'user.created', userId: row.id });
    return toUser(row);
  }

  async get(id: string): Promise<User | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('users').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toUser(row) : null;
  }

  async findByLogin(identifier: string): Promise<{ user: User; passwordHash: string | null } | null> {
    const value = identifier.trim().toLowerCase();
    if (!value) return null;
    const row = await this.db
      .selectFrom('users')
      .selectAll()
      .where((eb) =>
        eb.or([eb(eb.fn('lower', ['username']), '=', value), eb(eb.fn('lower', ['email']), '=', value)]),
      )
      .orderBy('created_at')
      .executeTakeFirst();
    return row ? { user: toUser(row), passwordHash: row.password_hash } : null;
  }

  async list(opts: { search?: string; limit?: number; offset?: number } = {}): Promise<User[]> {
    let query = this.db
      .selectFrom('users')
      .selectAll()
      .orderBy('username')
      .limit(opts.limit ?? 50)
      .offset(opts.offset ?? 0);
    if (opts.search) {
      const pattern = `%${escapeLike(opts.search)}%`;
      query = query.where((eb) =>
        eb.or([
          eb('username', 'ilike', pattern),
          eb('email', 'ilike', pattern),
          eb('display_name', 'ilike', pattern),
        ]),
      );
    }
    return (await query.execute()).map(toUser);
  }

  async count(): Promise<number> {
    const { n } = await this.db
      .selectFrom('users')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .executeTakeFirstOrThrow();
    return Number(n);
  }

  async update(id: string, input: UpdateUserInput): Promise<User> {
    const before = await this.get(id);
    if (!before) throw new NotFoundError('User not found');
    const patch = {
      ...(input.username !== undefined && { username: input.username }),
      ...(input.email !== undefined && { email: input.email }),
      ...(input.displayName !== undefined && { display_name: input.displayName }),
      ...(input.givenName !== undefined && { given_name: input.givenName }),
      ...(input.familyName !== undefined && { family_name: input.familyName }),
      ...(input.isAdmin !== undefined && { is_admin: input.isAdmin }),
      ...(input.isActive !== undefined && { is_active: input.isActive }),
    };
    if (Object.keys(patch).length === 0) return before;
    let row: Selectable<UsersTable>;
    try {
      row = await this.db
        .updateTable('users')
        .set({ ...patch, updated_at: new Date() })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    const deactivated = before.isActive && !row.is_active;
    await this.events.publish({ type: deactivated ? 'user.deactivated' : 'user.updated', userId: id });
    return toUser(row);
  }

  async setPassword(id: string, password: string | null): Promise<void> {
    const passwordHash = password === null ? null : await hashPassword(password);
    const result = isUuid(id)
      ? await this.db
          .updateTable('users')
          .set({ password_hash: passwordHash, updated_at: new Date() })
          .where('id', '=', id)
          .executeTakeFirst()
      : undefined;
    if (!result || result.numUpdatedRows === 0n) throw new NotFoundError('User not found');
  }

  async delete(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('users').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('User not found');
    await this.events.publish({ type: 'user.deleted', userId: id });
  }

  async groupNames(userId: string): Promise<string[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('groups', 'groups.id', 'group_members.group_id')
      .select('groups.name')
      .where('group_members.user_id', '=', userId)
      .orderBy('groups.name')
      .execute();
    return rows.map((r) => r.name);
  }
}
```

`src/identity/groups.ts`:
```ts
import { sql, type Selectable } from 'kysely';
import type { Db } from '../db/db.js';
import type { GroupsTable } from '../db/schema.js';
import { ConflictError, NotFoundError, isForeignKeyViolation, isUniqueViolation } from '../errors.js';
import type { EventBus } from '../events/bus.js';
import { isUuid } from '../util.js';
import { toUser, type User } from './users.js';

export interface Group {
  id: string;
  name: string;
  description: string;
  sourceId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

function toGroup(row: Selectable<GroupsTable>): Group {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    sourceId: row.source_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'A group with this name already exists';

export class GroupService {
  constructor(
    private readonly db: Db,
    private readonly events: EventBus,
  ) {}

  async create(input: { name: string; description?: string }): Promise<Group> {
    let row: Selectable<GroupsTable>;
    try {
      row = await this.db
        .insertInto('groups')
        .values({ name: input.name, description: input.description ?? '', source_id: null, external_id: null })
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'group.created', groupId: row.id });
    return toGroup(row);
  }

  async get(id: string): Promise<Group | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('groups').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toGroup(row) : null;
  }

  async list(): Promise<Group[]> {
    return (await this.db.selectFrom('groups').selectAll().orderBy('name').execute()).map(toGroup);
  }

  async update(id: string, input: { name?: string; description?: string }): Promise<Group> {
    const existing = await this.get(id);
    if (!existing) throw new NotFoundError('Group not found');
    const patch = {
      ...(input.name !== undefined && { name: input.name }),
      ...(input.description !== undefined && { description: input.description }),
    };
    if (Object.keys(patch).length === 0) return existing;
    let row: Selectable<GroupsTable>;
    try {
      row = await this.db
        .updateTable('groups')
        .set({ ...patch, updated_at: new Date() })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'group.updated', groupId: id });
    return toGroup(row);
  }

  async delete(id: string): Promise<void> {
    const group = await this.get(id);
    if (!group) throw new NotFoundError('Group not found');
    await this.db.transaction().execute(async (trx) => {
      await trx
        .updateTable('applications')
        .set({ allowed_group_ids: sql<string[]>`array_remove(allowed_group_ids, ${id}::uuid)` })
        .where(sql<boolean>`${id}::uuid = ANY(allowed_group_ids)`)
        .execute();
      await trx.deleteFrom('groups').where('id', '=', id).execute();
    });
    await this.events.publish({ type: 'group.deleted', groupId: id, name: group.name });
  }

  async listMembers(groupId: string): Promise<User[]> {
    if (!isUuid(groupId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('users', 'users.id', 'group_members.user_id')
      .selectAll('users')
      .where('group_members.group_id', '=', groupId)
      .orderBy('users.username')
      .execute();
    return rows.map(toUser);
  }

  async addMember(groupId: string, userId: string): Promise<void> {
    if (!isUuid(groupId) || !isUuid(userId)) throw new NotFoundError('User or group not found');
    let inserted: bigint;
    try {
      const result = await this.db
        .insertInto('group_members')
        .values({ group_id: groupId, user_id: userId })
        .onConflict((oc) => oc.doNothing())
        .executeTakeFirst();
      inserted = result.numInsertedOrUpdatedRows ?? 0n;
    } catch (err) {
      if (isForeignKeyViolation(err)) throw new NotFoundError('User or group not found');
      throw err;
    }
    if (inserted > 0n) {
      await this.events.publish({ type: 'group.members_changed', groupId, userIds: [userId] });
    }
  }

  async removeMember(groupId: string, userId: string): Promise<void> {
    if (!isUuid(groupId) || !isUuid(userId)) return;
    const result = await this.db
      .deleteFrom('group_members')
      .where('group_id', '=', groupId)
      .where('user_id', '=', userId)
      .executeTakeFirst();
    if (result.numDeletedRows > 0n) {
      await this.events.publish({ type: 'group.members_changed', groupId, userIds: [userId] });
    }
  }

  async groupsForUser(userId: string): Promise<Group[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('groups', 'groups.id', 'group_members.group_id')
      .selectAll('groups')
      .where('group_members.user_id', '=', userId)
      .orderBy('groups.name')
      .execute();
    return rows.map(toGroup);
  }

  async groupIdsForUser(userId: string): Promise<string[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .select('group_id')
      .where('user_id', '=', userId)
      .execute();
    return rows.map((r) => r.group_id);
  }

  async countExisting(ids: string[]): Promise<number> {
    const valid = ids.filter(isUuid);
    if (valid.length === 0) return 0;
    const { n } = await this.db
      .selectFrom('groups')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .where('id', 'in', valid)
      .executeTakeFirstOrThrow();
    return Number(n);
  }
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/identity && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/identity tests/identity
git commit -m "feat: add user and group services with domain events"
```

---

### Task 6: Sessions, login rate limiting and local authentication

**Files:**
- Create: `src/auth/sessions.ts`, `src/auth/rate-limit.ts`, `src/auth/local-login.ts`
- Test: `tests/auth/sessions.test.ts`, `tests/auth/local-login.test.ts`

**Interfaces:**
- Consumes: `Db`, `randomToken`, `hashToken`, `verifyPassword`, `UserService`, `User`, `AuditLog`.
- Produces:
  ```ts
  // sessions.ts
  export const SESSION_COOKIE = 'authi_session';
  export interface Session { id: string; userId: string; expiresAt: Date }
  export class SessionService {
    constructor(db: Db, ttlMs?: number);             // default 12h
    readonly ttlSeconds: number;
    create(userId: string, meta?: { ip?: string; userAgent?: string }): Promise<{ token: string; session: Session }>;
    validate(token: string | undefined | null): Promise<Session | null>;  // null if unknown, expired, or user inactive
    destroy(token: string): Promise<void>;
    destroyAllForUser(userId: string): Promise<void>;
    purgeExpired(): Promise<number>;
  }
  // rate-limit.ts
  export interface RateLimitOptions { windowMs: number; maxPerIp: number; maxPerUser: number }
  export class LoginRateLimiter {
    constructor(db: Db, opts?: Partial<RateLimitOptions>);  // defaults 15 min / 30 / 10
    isBlocked(ip: string, identifier: string): Promise<boolean>;
    recordFailure(ip: string, identifier: string): Promise<void>;
    clear(identifier: string): Promise<void>;
    purge(): Promise<void>;
  }
  // local-login.ts
  export type LoginResult = { ok: true; user: User } | { ok: false; reason: 'invalid_credentials' | 'inactive' | 'rate_limited' };
  export class LocalAuthenticator {
    constructor(users: UserService, limiter: LoginRateLimiter, audit: AuditLog);
    authenticate(identifier: string, password: string, ip: string): Promise<LoginResult>;
  }
  ```

- [ ] **Step 1: Write the failing tests**

`tests/auth/sessions.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SessionService } from '../../src/auth/sessions.js';
import { EventBus } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let sessions: SessionService;

beforeEach(async () => {
  t = await createTestDb();
  users = new UserService(t.db, new EventBus());
  sessions = new SessionService(t.db);
});
afterEach(() => t.destroy());

describe('SessionService', () => {
  it('creates and validates sessions; stores only a hash of the token', async () => {
    const u = await users.create({ username: 'alice' });
    const { token, session } = await sessions.create(u.id, { ip: '10.0.0.1', userAgent: 'test' });
    expect(session.userId).toBe(u.id);
    expect((await sessions.validate(token))?.id).toBe(session.id);
    const raw = await t.db.selectFrom('sessions').select('token_hash').executeTakeFirstOrThrow();
    expect(raw.token_hash).not.toBe(token);
    expect(sessions.ttlSeconds).toBe(12 * 60 * 60);
  });

  it('rejects unknown, empty and expired tokens', async () => {
    const u = await users.create({ username: 'alice' });
    expect(await sessions.validate('nope')).toBeNull();
    expect(await sessions.validate(undefined)).toBeNull();
    const shortLived = new SessionService(t.db, 1);
    const { token } = await shortLived.create(u.id);
    await new Promise((r) => setTimeout(r, 10));
    expect(await shortLived.validate(token)).toBeNull();
    expect(await shortLived.purgeExpired()).toBe(1);
  });

  it('rejects sessions of deactivated users', async () => {
    const u = await users.create({ username: 'alice' });
    const { token } = await sessions.create(u.id);
    await users.update(u.id, { isActive: false });
    expect(await sessions.validate(token)).toBeNull();
  });

  it('destroys one or all sessions', async () => {
    const u = await users.create({ username: 'alice' });
    const a = await sessions.create(u.id);
    const b = await sessions.create(u.id);
    await sessions.destroy(a.token);
    expect(await sessions.validate(a.token)).toBeNull();
    expect(await sessions.validate(b.token)).not.toBeNull();
    await sessions.destroyAllForUser(u.id);
    expect(await sessions.validate(b.token)).toBeNull();
  });
});
```

`tests/auth/local-login.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit/audit.js';
import { LocalAuthenticator } from '../../src/auth/local-login.js';
import { LoginRateLimiter } from '../../src/auth/rate-limit.js';
import { EventBus } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

const PASSWORD = 'correct-horse-battery';
let t: TestDb;
let users: UserService;
let audit: AuditLog;
let auth: LocalAuthenticator;

beforeEach(async () => {
  t = await createTestDb();
  users = new UserService(t.db, new EventBus());
  audit = new AuditLog(t.db);
  auth = new LocalAuthenticator(users, new LoginRateLimiter(t.db, { maxPerUser: 3, maxPerIp: 5 }), audit);
  await users.create({ username: 'alice', email: 'alice@example.com', password: PASSWORD });
});
afterEach(() => t.destroy());

describe('LocalAuthenticator', () => {
  it('accepts username or email in any case', async () => {
    for (const id of ['alice', 'ALICE', 'Alice@Example.com', '  alice  ']) {
      const r = await auth.authenticate(id, PASSWORD, '10.0.0.1');
      expect(r.ok).toBe(true);
    }
    const actions = (await audit.list()).map((e) => e.action);
    expect(actions.every((a) => a === 'login.success')).toBe(true);
  });

  it('rejects a wrong password and unknown users alike', async () => {
    expect(await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1')).toEqual({
      ok: false,
      reason: 'invalid_credentials',
    });
    expect(await auth.authenticate('mallory', PASSWORD, '10.0.0.1')).toEqual({
      ok: false,
      reason: 'invalid_credentials',
    });
    expect((await audit.list()).map((e) => e.action)).toEqual(['login.failed', 'login.failed']);
  });

  it('rejects inactive users', async () => {
    const found = await users.findByLogin('alice');
    await users.update(found!.user.id, { isActive: false });
    expect(await auth.authenticate('alice', PASSWORD, '10.0.0.1')).toEqual({ ok: false, reason: 'inactive' });
  });

  it('rate-limits per user regardless of identifier case, even with the right password', async () => {
    for (const id of ['alice', 'ALICE', 'Alice']) await auth.authenticate(id, 'wrong-password-1', `10.0.0.${id.length}`);
    expect(await auth.authenticate('alice', PASSWORD, '10.9.9.9')).toEqual({ ok: false, reason: 'rate_limited' });
  });

  it('rate-limits per ip across usernames', async () => {
    for (let i = 0; i < 5; i++) await auth.authenticate(`user${i}`, 'wrong-password-1', '10.0.0.7');
    expect(await auth.authenticate('alice', PASSWORD, '10.0.0.7')).toEqual({ ok: false, reason: 'rate_limited' });
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.8')).ok).toBe(true);
  });

  it('clears the per-user counter after a successful login', async () => {
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.1')).ok).toBe(true);
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.1')).ok).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/auth`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement**

`src/auth/sessions.ts`:
```ts
import { hashToken, randomToken } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import { isUuid } from '../util.js';

export const SESSION_COOKIE = 'authi_session';

export interface Session {
  id: string;
  userId: string;
  expiresAt: Date;
}

const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

export class SessionService {
  constructor(
    private readonly db: Db,
    private readonly ttlMs: number = DEFAULT_TTL_MS,
  ) {}

  get ttlSeconds(): number {
    return Math.floor(this.ttlMs / 1000);
  }

  async create(userId: string, meta: { ip?: string; userAgent?: string } = {}): Promise<{ token: string; session: Session }> {
    const token = randomToken();
    const row = await this.db
      .insertInto('sessions')
      .values({
        token_hash: hashToken(token),
        user_id: userId,
        expires_at: new Date(Date.now() + this.ttlMs),
        ip: meta.ip ?? null,
        user_agent: meta.userAgent?.slice(0, 512) ?? null,
      })
      .returning(['id', 'user_id', 'expires_at'])
      .executeTakeFirstOrThrow();
    return { token, session: { id: row.id, userId: row.user_id, expiresAt: row.expires_at } };
  }

  async validate(token: string | undefined | null): Promise<Session | null> {
    if (!token) return null;
    const row = await this.db
      .selectFrom('sessions')
      .innerJoin('users', 'users.id', 'sessions.user_id')
      .select(['sessions.id', 'sessions.user_id', 'sessions.expires_at'])
      .where('sessions.token_hash', '=', hashToken(token))
      .where('sessions.expires_at', '>', new Date())
      .where('users.is_active', '=', true)
      .executeTakeFirst();
    if (!row) return null;
    await this.db.updateTable('sessions').set({ last_seen_at: new Date() }).where('id', '=', row.id).execute();
    return { id: row.id, userId: row.user_id, expiresAt: row.expires_at };
  }

  async destroy(token: string): Promise<void> {
    await this.db.deleteFrom('sessions').where('token_hash', '=', hashToken(token)).execute();
  }

  async destroyAllForUser(userId: string): Promise<void> {
    if (!isUuid(userId)) return;
    await this.db.deleteFrom('sessions').where('user_id', '=', userId).execute();
  }

  async purgeExpired(): Promise<number> {
    const result = await this.db.deleteFrom('sessions').where('expires_at', '<=', new Date()).executeTakeFirst();
    return Number(result.numDeletedRows);
  }
}
```

`src/auth/rate-limit.ts`:
```ts
import type { Db } from '../db/db.js';

export interface RateLimitOptions {
  windowMs: number;
  maxPerIp: number;
  maxPerUser: number;
}

const DEFAULTS: RateLimitOptions = { windowMs: 15 * 60 * 1000, maxPerIp: 30, maxPerUser: 10 };

const ipKey = (ip: string) => `ip:${ip}`;
const userKey = (identifier: string) => `user:${identifier.trim().toLowerCase()}`;

export class LoginRateLimiter {
  private readonly opts: RateLimitOptions;

  constructor(
    private readonly db: Db,
    opts: Partial<RateLimitOptions> = {},
  ) {
    this.opts = { ...DEFAULTS, ...opts };
  }

  async isBlocked(ip: string, identifier: string): Promise<boolean> {
    const since = new Date(Date.now() - this.opts.windowMs);
    const rows = await this.db
      .selectFrom('login_attempts')
      .select(['key', (eb) => eb.fn.countAll<string>().as('n')])
      .where('key', 'in', [ipKey(ip), userKey(identifier)])
      .where('at', '>', since)
      .groupBy('key')
      .execute();
    return rows.some((r) =>
      r.key === ipKey(ip) ? Number(r.n) >= this.opts.maxPerIp : Number(r.n) >= this.opts.maxPerUser,
    );
  }

  async recordFailure(ip: string, identifier: string): Promise<void> {
    await this.db
      .insertInto('login_attempts')
      .values([{ key: ipKey(ip) }, { key: userKey(identifier) }])
      .execute();
  }

  async clear(identifier: string): Promise<void> {
    await this.db.deleteFrom('login_attempts').where('key', '=', userKey(identifier)).execute();
  }

  async purge(): Promise<void> {
    await this.db
      .deleteFrom('login_attempts')
      .where('at', '<', new Date(Date.now() - this.opts.windowMs))
      .execute();
  }
}
```

`src/auth/local-login.ts`:
```ts
import type { AuditLog } from '../audit/audit.js';
import { verifyPassword } from '../crypto/passwords.js';
import type { User, UserService } from '../identity/users.js';
import type { LoginRateLimiter } from './rate-limit.js';

export type LoginResult =
  | { ok: true; user: User }
  | { ok: false; reason: 'invalid_credentials' | 'inactive' | 'rate_limited' };

export class LocalAuthenticator {
  constructor(
    private readonly users: UserService,
    private readonly limiter: LoginRateLimiter,
    private readonly audit: AuditLog,
  ) {}

  async authenticate(identifier: string, password: string, ip: string): Promise<LoginResult> {
    const id = identifier.trim();
    if (await this.limiter.isBlocked(ip, id)) {
      await this.audit.record({ actor: { type: 'anonymous' }, action: 'login.rate_limited', details: { identifier: id }, ip });
      return { ok: false, reason: 'rate_limited' };
    }
    const found = await this.users.findByLogin(id);
    const valid = await verifyPassword(found?.passwordHash ?? null, password);
    if (!found || !valid) {
      await this.limiter.recordFailure(ip, id);
      await this.audit.record({ actor: { type: 'anonymous' }, action: 'login.failed', details: { identifier: id }, ip });
      return { ok: false, reason: 'invalid_credentials' };
    }
    if (!found.user.isActive) {
      await this.limiter.recordFailure(ip, id);
      await this.audit.record({
        actor: { type: 'user', id: found.user.id },
        action: 'login.failed',
        details: { reason: 'inactive' },
        ip,
      });
      return { ok: false, reason: 'inactive' };
    }
    await this.limiter.clear(id);
    await this.audit.record({ actor: { type: 'user', id: found.user.id }, action: 'login.success', details: { source: 'local' }, ip });
    return { ok: true, user: found.user };
  }
}
```

Note: the per-user key is the identifier as typed (lower-cased), so `alice` and `alice@example.com` are separate buckets; the per-IP limit covers switching identifiers.

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/auth && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auth tests/auth
git commit -m "feat: add sessions, login rate limiting and local authentication"
```

---
### Task 7: Redirect validation and access policy

**Files:**
- Create: `src/auth/redirects.ts`, `src/apps/policy.ts`
- Test: `tests/auth/redirects.test.ts`, `tests/apps/policy.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```ts
  // redirects.ts
  export interface RedirectRules { issuerUrl: string; cookieDomain?: string; allowedHosts?: readonly string[] }
  export function isSafeRedirect(target: string, rules: RedirectRules): boolean;
  export function safeRedirectTarget(target: unknown, rules: RedirectRules, fallback?: string): string; // fallback '/'
  // policy.ts
  export function canAccess(user: { isActive: boolean }, userGroupIds: readonly string[], app: { allowedGroupIds: readonly string[] }): boolean;
  ```

- [ ] **Step 1: Write the failing tests**

`tests/auth/redirects.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { isSafeRedirect, safeRedirectTarget, type RedirectRules } from '../../src/auth/redirects.js';

const rules: RedirectRules = {
  issuerUrl: 'https://auth.example.com',
  cookieDomain: '.example.com',
  allowedHosts: ['grafana.homelab.net'],
};

describe('isSafeRedirect', () => {
  it.each([
    '/',
    '/interaction/abc',
    '/path?x=1#y',
    'https://auth.example.com/anything',
    'https://example.com/',
    'https://app.example.com/dashboard',
    'http://app.example.com/',
    'https://deep.sub.example.com/',
    'https://GRAFANA.homelab.net/d/1',
  ])('accepts %s', (target) => {
    expect(isSafeRedirect(target, rules)).toBe(true);
  });

  it.each([
    '//evil.com',
    '/\\evil.com',
    '/\t/evil.com',
    '/\n/evil.com',
    'https://evil.com',
    'https://example.com.evil.com',
    'https://evilexample.com',
    'https://user:pass@app.example.com/',
    'javascript:alert(1)',
    'data:text/html,hi',
    'ftp://app.example.com',
    'relative/path',
    '',
  ])('rejects %j', (target) => {
    expect(isSafeRedirect(target, rules)).toBe(false);
  });

  it('only allows the issuer host when no cookie domain is set', () => {
    const strict = { issuerUrl: 'https://auth.example.com' };
    expect(isSafeRedirect('https://auth.example.com/x', strict)).toBe(true);
    expect(isSafeRedirect('https://app.example.com/x', strict)).toBe(false);
  });
});

describe('safeRedirectTarget', () => {
  it('falls back for unsafe or non-string input', () => {
    expect(safeRedirectTarget('https://evil.com', rules)).toBe('/');
    expect(safeRedirectTarget(undefined, rules)).toBe('/');
    expect(safeRedirectTarget(['/a'], rules)).toBe('/');
    expect(safeRedirectTarget('/ok', rules)).toBe('/ok');
  });
});
```

`tests/apps/policy.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { canAccess } from '../../src/apps/policy.js';

describe('canAccess', () => {
  const active = { isActive: true };
  it('allows every active user when the app has no group restriction', () => {
    expect(canAccess(active, [], { allowedGroupIds: [] })).toBe(true);
  });
  it('requires membership of any allowed group', () => {
    const app = { allowedGroupIds: ['g1', 'g2'] };
    expect(canAccess(active, ['g2'], app)).toBe(true);
    expect(canAccess(active, ['g3'], app)).toBe(false);
    expect(canAccess(active, [], app)).toBe(false);
  });
  it('never allows inactive users', () => {
    expect(canAccess({ isActive: false }, ['g1'], { allowedGroupIds: [] })).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/auth/redirects.test.ts tests/apps/policy.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement**

`src/auth/redirects.ts`:
```ts
export interface RedirectRules {
  issuerUrl: string;
  cookieDomain?: string;
  allowedHosts?: readonly string[];
}

// Backslashes and control characters are normalised away by browsers ("/\evil" → "//evil").
const UNSAFE_RELATIVE = /[\\\u0000-\u001f\u007f]/;

export function isSafeRedirect(target: string, rules: RedirectRules): boolean {
  if (target.startsWith('/')) {
    return !target.startsWith('//') && !UNSAFE_RELATIVE.test(target);
  }
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (host === new URL(rules.issuerUrl).hostname.toLowerCase()) return true;
  if (rules.allowedHosts?.some((h) => h.toLowerCase() === host)) return true;
  if (rules.cookieDomain) {
    const domain = rules.cookieDomain.replace(/^\./, '').toLowerCase();
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

export function safeRedirectTarget(target: unknown, rules: RedirectRules, fallback = '/'): string {
  return typeof target === 'string' && isSafeRedirect(target, rules) ? target : fallback;
}
```

`src/apps/policy.ts`:
```ts
export function canAccess(
  user: { isActive: boolean },
  userGroupIds: readonly string[],
  app: { allowedGroupIds: readonly string[] },
): boolean {
  if (!user.isActive) return false;
  if (app.allowedGroupIds.length === 0) return true;
  return app.allowedGroupIds.some((id) => userGroupIds.includes(id));
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/auth/redirects.test.ts tests/apps/policy.test.ts && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auth/redirects.ts src/apps/policy.ts tests/auth/redirects.test.ts tests/apps/policy.test.ts
git commit -m "feat: add redirect validation and app access policy"
```

---

### Task 8: Applications

**Files:**
- Create: `src/apps/applications.ts`
- Test: `tests/apps/applications.test.ts`

**Interfaces:**
- Consumes: `Db`, `SecretBox`, `randomToken`, `GroupService.countExisting`, `ConflictError`, `NotFoundError`, `ValidationError`, `isUniqueViolation`, `isUuid`, `TokenEndpointAuthMethod`.
- Produces:
  ```ts
  export interface Application { id: string; slug: string; name: string; oidcEnabled: boolean; forwardAuthEnabled: boolean;
    clientId: string; tokenEndpointAuthMethod: TokenEndpointAuthMethod; redirectUris: string[]; postLogoutRedirectUris: string[];
    externalHost: string | null; allowedGroupIds: string[]; launchUrl: string | null; createdAt: Date; updatedAt: Date }
  export interface CreateApplicationInput { slug: string; name: string; oidcEnabled?: boolean; forwardAuthEnabled?: boolean;
    tokenEndpointAuthMethod?: TokenEndpointAuthMethod; redirectUris?: string[]; postLogoutRedirectUris?: string[];
    externalHost?: string | null; allowedGroupIds?: string[]; launchUrl?: string | null }
  export type UpdateApplicationInput = Partial<Omit<CreateApplicationInput, 'slug'>>;
  export interface OidcClientMetadata { client_id: string; client_secret: string; client_name: string; redirect_uris: string[];
    post_logout_redirect_uris: string[]; grant_types: string[]; response_types: string[]; token_endpoint_auth_method: string }
  export class ApplicationService {
    constructor(db: Db, box: SecretBox, groups: GroupService);
    create(input: CreateApplicationInput): Promise<{ application: Application; clientSecret: string }>;
    get(id: string): Promise<Application | null>;
    getByClientId(clientId: string): Promise<Application | null>;
    getByExternalHost(host: string): Promise<Application | null>;   // host without port, case-insensitive
    list(): Promise<Application[]>;
    update(id: string, input: UpdateApplicationInput): Promise<Application>;
    delete(id: string): Promise<void>;
    rotateSecret(id: string): Promise<string>;
    forwardAuthHosts(): Promise<string[]>;
    oidcClientMetadata(clientId: string): Promise<OidcClientMetadata | undefined>;
  }
  ```

- [ ] **Step 1: Write the failing test** — `tests/apps/applications.test.ts`

```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApplicationService } from '../../src/apps/applications.js';
import { createSecretBox } from '../../src/crypto/secrets.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/errors.js';
import { EventBus } from '../../src/events/bus.js';
import { GroupService } from '../../src/identity/groups.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let apps: ApplicationService;
let groups: GroupService;

beforeEach(async () => {
  t = await createTestDb();
  groups = new GroupService(t.db, new EventBus());
  apps = new ApplicationService(t.db, createSecretBox(Buffer.alloc(32, 9)), groups);
});
afterEach(() => t.destroy());

const oidcApp = {
  slug: 'demo',
  name: 'Demo',
  oidcEnabled: true,
  redirectUris: ['https://demo.example.com/callback'],
};

describe('ApplicationService', () => {
  it('creates an app whose client_id is the slug and returns the secret once', async () => {
    const { application, clientSecret } = await apps.create(oidcApp);
    expect(application).toMatchObject({
      slug: 'demo',
      clientId: 'demo',
      oidcEnabled: true,
      forwardAuthEnabled: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      allowedGroupIds: [],
    });
    expect(clientSecret.length).toBeGreaterThanOrEqual(43);
    expect(application).not.toHaveProperty('clientSecret');
    const raw = await t.db.selectFrom('applications').select('client_secret_enc').executeTakeFirstOrThrow();
    expect(raw.client_secret_enc).not.toContain(clientSecret);
  });

  it('serves OIDC client metadata with the decrypted secret, only when OIDC is enabled', async () => {
    const { clientSecret } = await apps.create(oidcApp);
    expect(await apps.oidcClientMetadata('demo')).toEqual({
      client_id: 'demo',
      client_secret: clientSecret,
      client_name: 'Demo',
      redirect_uris: ['https://demo.example.com/callback'],
      post_logout_redirect_uris: [],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    });
    await apps.create({ slug: 'proxy-only', name: 'Proxy', forwardAuthEnabled: true, externalHost: 'p.example.com' });
    expect(await apps.oidcClientMetadata('proxy-only')).toBeUndefined();
    expect(await apps.oidcClientMetadata('unknown')).toBeUndefined();
  });

  it('enforces consistency rules', async () => {
    await expect(apps.create({ slug: 'a1', name: 'A', oidcEnabled: true })).rejects.toBeInstanceOf(ValidationError);
    await expect(apps.create({ slug: 'a2', name: 'A', forwardAuthEnabled: true })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(
      apps.create({ ...oidcApp, slug: 'a3', allowedGroupIds: ['00000000-0000-0000-0000-000000000000'] }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('rejects duplicate slugs and external hosts', async () => {
    await apps.create({ ...oidcApp, forwardAuthEnabled: true, externalHost: 'demo.example.com' });
    await expect(apps.create(oidcApp)).rejects.toBeInstanceOf(ConflictError);
    await expect(
      apps.create({ slug: 'other', name: 'O', forwardAuthEnabled: true, externalHost: 'DEMO.example.com' }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('finds forward-auth apps by host, case-insensitively, and lists their hosts', async () => {
    await apps.create({ slug: 'proxy', name: 'Proxy', forwardAuthEnabled: true, externalHost: 'Proxy.Example.com' });
    await apps.create(oidcApp);
    expect((await apps.getByExternalHost('proxy.example.COM'))?.slug).toBe('proxy');
    expect(await apps.getByExternalHost('nope.example.com')).toBeNull();
    expect(await apps.forwardAuthHosts()).toEqual(['proxy.example.com']);
  });

  it('updates apps and validates the merged result', async () => {
    const g = await groups.create({ name: 'staff' });
    const { application } = await apps.create(oidcApp);
    const updated = await apps.update(application.id, { name: 'Demo 2', allowedGroupIds: [g.id] });
    expect(updated).toMatchObject({ name: 'Demo 2', allowedGroupIds: [g.id] });
    await expect(apps.update(application.id, { redirectUris: [] })).rejects.toBeInstanceOf(ValidationError);
    await expect(apps.update('00000000-0000-0000-0000-000000000000', { name: 'x' })).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('rotates the secret', async () => {
    const { application, clientSecret } = await apps.create(oidcApp);
    const next = await apps.rotateSecret(application.id);
    expect(next).not.toBe(clientSecret);
    expect((await apps.oidcClientMetadata('demo'))?.client_secret).toBe(next);
  });

  it('deletes apps', async () => {
    const { application } = await apps.create(oidcApp);
    await apps.delete(application.id);
    expect(await apps.get(application.id)).toBeNull();
    await expect(apps.delete(application.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/apps/applications.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement** — `src/apps/applications.ts`

```ts
import type { Selectable } from 'kysely';
import { randomToken, type SecretBox } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import type { ApplicationsTable, TokenEndpointAuthMethod } from '../db/schema.js';
import { ConflictError, NotFoundError, ValidationError, isUniqueViolation } from '../errors.js';
import type { GroupService } from '../identity/groups.js';
import { isUuid } from '../util.js';

export interface Application {
  id: string;
  slug: string;
  name: string;
  oidcEnabled: boolean;
  forwardAuthEnabled: boolean;
  clientId: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  externalHost: string | null;
  allowedGroupIds: string[];
  launchUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateApplicationInput {
  slug: string;
  name: string;
  oidcEnabled?: boolean;
  forwardAuthEnabled?: boolean;
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  externalHost?: string | null;
  allowedGroupIds?: string[];
  launchUrl?: string | null;
}

export type UpdateApplicationInput = Partial<Omit<CreateApplicationInput, 'slug'>>;

export interface OidcClientMetadata {
  client_id: string;
  client_secret: string;
  client_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
}

type Row = Selectable<ApplicationsTable>;

function toApplication(row: Row): Application {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    oidcEnabled: row.oidc_enabled,
    forwardAuthEnabled: row.forward_auth_enabled,
    clientId: row.client_id,
    tokenEndpointAuthMethod: row.token_endpoint_auth_method,
    redirectUris: row.redirect_uris,
    postLogoutRedirectUris: row.post_logout_redirect_uris,
    externalHost: row.external_host,
    allowedGroupIds: row.allowed_group_ids,
    launchUrl: row.launch_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'An application with this slug or external host already exists';

export class ApplicationService {
  constructor(
    private readonly db: Db,
    private readonly box: SecretBox,
    private readonly groups: GroupService,
  ) {}

  private async assertConsistent(app: {
    oidcEnabled: boolean;
    forwardAuthEnabled: boolean;
    redirectUris: string[];
    externalHost: string | null;
    allowedGroupIds: string[];
  }): Promise<void> {
    if (app.oidcEnabled && app.redirectUris.length === 0) {
      throw new ValidationError('OIDC applications need at least one redirect URI');
    }
    if (app.forwardAuthEnabled && !app.externalHost) {
      throw new ValidationError('Forward-auth applications need an external host');
    }
    const unique = [...new Set(app.allowedGroupIds)];
    if ((await this.groups.countExisting(unique)) !== unique.length) {
      throw new ValidationError('allowedGroupIds contains unknown groups');
    }
  }

  async create(input: CreateApplicationInput): Promise<{ application: Application; clientSecret: string }> {
    const values = {
      oidcEnabled: input.oidcEnabled ?? false,
      forwardAuthEnabled: input.forwardAuthEnabled ?? false,
      redirectUris: input.redirectUris ?? [],
      externalHost: input.externalHost?.toLowerCase() ?? null,
      allowedGroupIds: [...new Set(input.allowedGroupIds ?? [])],
    };
    await this.assertConsistent(values);
    const clientSecret = randomToken(32);
    try {
      const row = await this.db
        .insertInto('applications')
        .values({
          slug: input.slug,
          name: input.name,
          oidc_enabled: values.oidcEnabled,
          forward_auth_enabled: values.forwardAuthEnabled,
          client_id: input.slug,
          client_secret_enc: this.box.encrypt(clientSecret),
          token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? 'client_secret_basic',
          redirect_uris: values.redirectUris,
          post_logout_redirect_uris: input.postLogoutRedirectUris ?? [],
          external_host: values.externalHost,
          allowed_group_ids: values.allowedGroupIds,
          launch_url: input.launchUrl ?? null,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
      return { application: toApplication(row), clientSecret };
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
  }

  async get(id: string): Promise<Application | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('applications').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async getByClientId(clientId: string): Promise<Application | null> {
    const row = await this.db.selectFrom('applications').selectAll().where('client_id', '=', clientId).executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async getByExternalHost(host: string): Promise<Application | null> {
    const row = await this.db
      .selectFrom('applications')
      .selectAll()
      .where((eb) => eb(eb.fn('lower', ['external_host']), '=', host.toLowerCase()))
      .executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async list(): Promise<Application[]> {
    return (await this.db.selectFrom('applications').selectAll().orderBy('name').execute()).map(toApplication);
  }

  async update(id: string, input: UpdateApplicationInput): Promise<Application> {
    const existing = await this.get(id);
    if (!existing) throw new NotFoundError('Application not found');
    const merged = {
      oidcEnabled: input.oidcEnabled ?? existing.oidcEnabled,
      forwardAuthEnabled: input.forwardAuthEnabled ?? existing.forwardAuthEnabled,
      redirectUris: input.redirectUris ?? existing.redirectUris,
      externalHost: input.externalHost === undefined ? existing.externalHost : (input.externalHost?.toLowerCase() ?? null),
      allowedGroupIds: input.allowedGroupIds ? [...new Set(input.allowedGroupIds)] : existing.allowedGroupIds,
    };
    await this.assertConsistent(merged);
    try {
      const row = await this.db
        .updateTable('applications')
        .set({
          name: input.name ?? existing.name,
          oidc_enabled: merged.oidcEnabled,
          forward_auth_enabled: merged.forwardAuthEnabled,
          token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod,
          redirect_uris: merged.redirectUris,
          post_logout_redirect_uris: input.postLogoutRedirectUris ?? existing.postLogoutRedirectUris,
          external_host: merged.externalHost,
          allowed_group_ids: merged.allowedGroupIds,
          launch_url: input.launchUrl === undefined ? existing.launchUrl : input.launchUrl,
          updated_at: new Date(),
        })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
      return toApplication(row);
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
  }

  async delete(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('applications').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('Application not found');
  }

  async rotateSecret(id: string): Promise<string> {
    const clientSecret = randomToken(32);
    const row = isUuid(id)
      ? await this.db
          .updateTable('applications')
          .set({ client_secret_enc: this.box.encrypt(clientSecret), updated_at: new Date() })
          .where('id', '=', id)
          .returning('id')
          .executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('Application not found');
    return clientSecret;
  }

  async forwardAuthHosts(): Promise<string[]> {
    const rows = await this.db
      .selectFrom('applications')
      .select('external_host')
      .where('forward_auth_enabled', '=', true)
      .where('external_host', 'is not', null)
      .orderBy('external_host')
      .execute();
    return rows.map((r) => r.external_host!);
  }

  async oidcClientMetadata(clientId: string): Promise<OidcClientMetadata | undefined> {
    const row = await this.db
      .selectFrom('applications')
      .selectAll()
      .where('client_id', '=', clientId)
      .where('oidc_enabled', '=', true)
      .executeTakeFirst();
    if (!row) return undefined;
    return {
      client_id: row.client_id,
      client_secret: this.box.decrypt(row.client_secret_enc),
      client_name: row.name,
      redirect_uris: row.redirect_uris,
      post_logout_redirect_uris: row.post_logout_redirect_uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: row.token_endpoint_auth_method,
    };
  }
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/apps && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/apps/applications.ts tests/apps/applications.test.ts
git commit -m "feat: add application registry with encrypted client secrets"
```

---
### Task 9: HTTP app, service container and login pages

**Files:**
- Create: `src/services.ts`, `src/http/app.ts`, `src/http/views.ts`, `src/http/csrf.ts`, `src/http/context.ts`, `src/http/login-routes.ts`
- Create: `views/layout.eta`, `views/login.eta`, `views/home.eta`, `views/error.eta`
- Create: `tests/helpers/app.ts`
- Test: `tests/http/login.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces:
  ```ts
  // services.ts (extended in Tasks 10, 11, 12)
  export interface Services { config: Config; db: Db; box: SecretBox; events: EventBus; audit: AuditLog; users: UserService;
    groups: GroupService; sessions: SessionService; limiter: LoginRateLimiter; localAuth: LocalAuthenticator; apps: ApplicationService }
  export function createServices(config: Config, db: Db, opts?: { onEventError?: (err: unknown, event: DomainEvent) => void }): Services;
  // http/app.ts
  export function buildApp(s: Services, opts?: { logger?: boolean | { level: string } }): Promise<FastifyInstance>;
  // http/views.ts
  export function renderPage(reply: FastifyReply, template: string, data: Record<string, unknown>): FastifyReply;
  // http/csrf.ts
  export const CSRF_COOKIE = 'authi_csrf';
  export function issueCsrfToken(req: FastifyRequest, reply: FastifyReply, config: Config): string;
  export function verifyCsrfToken(req: FastifyRequest, submitted: unknown): boolean;
  // http/context.ts
  export function currentUser(req: FastifyRequest, s: Pick<Services, 'sessions' | 'users'>): Promise<User | null>;
  export function sessionCookieOptions(config: Config, maxAgeSeconds?: number): CookieSerializeOptions;
  export function redirectRules(s: Pick<Services, 'config' | 'apps'>): Promise<RedirectRules>;
  // tests/helpers/app.ts
  export const TEST_PASSWORD = 'correct-horse-battery';
  export function testConfig(overrides?: Partial<Config>): Config;
  export interface TestContext { services: Services; app: FastifyInstance; close(): Promise<void> }
  export function createTestContext(overrides?: Partial<Config>): Promise<TestContext>;
  ```
- Routes: `GET /healthz`, `GET /login?rd=`, `POST /login` (form: `csrf`, `rd`, `identifier`, `password`), `GET|POST /logout`, `GET /`.

- [ ] **Step 1: Write the test helper** — `tests/helpers/app.ts`

```ts
import type { FastifyInstance } from 'fastify';
import type { Config } from '../../src/config.js';
import { buildApp } from '../../src/http/app.js';
import { createServices, type Services } from '../../src/services.js';
import { createTestDb } from './db.js';

export const TEST_PASSWORD = 'correct-horse-battery';

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    issuerUrl: 'http://127.0.0.1:9000',
    cookieDomain: undefined,
    secureCookies: false,
    secretKey: Buffer.alloc(32, 1),
    databaseUrl: '',
    bootstrapAdmin: undefined,
    trustProxy: 'loopback',
    port: 9000,
    logLevel: 'silent',
    ...overrides,
  };
}

export interface TestContext {
  services: Services;
  app: FastifyInstance;
  close(): Promise<void>;
}

export async function createTestContext(overrides: Partial<Config> = {}): Promise<TestContext> {
  const tdb = await createTestDb();
  const services = createServices(testConfig({ databaseUrl: tdb.url, ...overrides }), tdb.db);
  const app = await buildApp(services);
  return {
    services,
    app,
    async close() {
      await app.close();
      await tdb.destroy();
    },
  };
}
```

- [ ] **Step 2: Write the failing test** — `tests/http/login.test.ts`

```ts
import type { Response as InjectResponse } from 'light-my-request';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, TEST_PASSWORD, type TestContext } from '../helpers/app.js';

let ctx: TestContext;

beforeEach(async () => {
  ctx = await createTestContext({
    issuerUrl: 'https://auth.example.test',
    secureCookies: true,
    cookieDomain: '.example.test',
  });
  await ctx.services.users.create({ username: 'alice', email: 'alice@example.test', password: TEST_PASSWORD });
});
afterEach(() => ctx.close());

const cookie = (res: InjectResponse, name: string) =>
  (res.cookies as Array<{ name: string; value: string; [k: string]: unknown }>).find((c) => c.name === name);

async function loginForm(query = '') {
  const res = await ctx.app.inject({ method: 'GET', url: `/login${query}` });
  return { res, csrf: cookie(res, 'authi_csrf')!.value };
}

function postLogin(fields: Record<string, string>, cookies: Record<string, string> = {}) {
  return ctx.app.inject({
    method: 'POST',
    url: '/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(fields).toString(),
    cookies,
  });
}

async function signIn(rd = '/') {
  const { csrf } = await loginForm();
  return postLogin({ csrf, rd, identifier: 'alice', password: TEST_PASSWORD }, { authi_csrf: csrf });
}

describe('login pages', () => {
  it('renders the login form with a CSRF token and security headers', async () => {
    const { res, csrf } = await loginForm('?rd=%2Fsomewhere');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain(`name="csrf" value="${csrf}"`);
    expect(res.body).toContain('name="rd" value="/somewhere"');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['strict-transport-security']).toBeDefined();
  });

  it('rejects a POST without a matching CSRF token', async () => {
    const res = await postLogin({ csrf: 'forged', identifier: 'alice', password: TEST_PASSWORD });
    expect(res.statusCode).toBe(403);
    expect(cookie(res, 'authi_session')).toBeUndefined();
  });

  it('shows an error for wrong credentials and keeps the identifier', async () => {
    const { csrf } = await loginForm();
    const res = await postLogin({ csrf, identifier: 'alice', password: 'wrong-password-1' }, { authi_csrf: csrf });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('Invalid username or password.');
    expect(res.body).toContain('value="alice"');
  });

  it('signs in, sets a secure session cookie on the cookie domain and shows the home page', async () => {
    const res = await signIn();
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/');
    const session = cookie(res, 'authi_session')!;
    expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', domain: '.example.test', path: '/' });
    const home = await ctx.app.inject({ method: 'GET', url: '/', cookies: { authi_session: session.value } });
    expect(home.statusCode).toBe(200);
    expect(home.body).toContain('alice');
  });

  it('only redirects to safe targets after sign-in', async () => {
    expect((await signIn('https://evil.test/')).headers.location).toBe('/');
    expect((await signIn('https://app.example.test/x')).headers.location).toBe('https://app.example.test/x');
  });

  it('allows redirects to forward-auth hosts outside the cookie domain', async () => {
    await ctx.services.apps.create({ slug: 'nas', name: 'NAS', forwardAuthEnabled: true, externalHost: 'nas.other.test' });
    expect((await signIn('https://nas.other.test/files')).headers.location).toBe('https://nas.other.test/files');
  });

  it('redirects an already signed-in user straight to rd', async () => {
    const token = cookie(await signIn(), 'authi_session')!.value;
    const res = await ctx.app.inject({ method: 'GET', url: '/login?rd=%2Fnext', cookies: { authi_session: token } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/next');
  });

  it('signs out and invalidates the session', async () => {
    const token = cookie(await signIn(), 'authi_session')!.value;
    const res = await ctx.app.inject({ method: 'POST', url: '/logout', cookies: { authi_session: token } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/login?loggedOut=1');
    expect(cookie(res, 'authi_session')?.value).toBe('');
    expect(await ctx.services.sessions.validate(token)).toBeNull();
    const home = await ctx.app.inject({ method: 'GET', url: '/', cookies: { authi_session: token } });
    expect(home.headers.location).toBe('/login');
  });

  it('answers 429 when rate limited', async () => {
    const { csrf } = await loginForm();
    let res: InjectResponse | undefined;
    for (let i = 0; i < 11; i++) {
      res = await postLogin({ csrf, identifier: 'alice', password: 'wrong-password-1' }, { authi_csrf: csrf });
    }
    expect(res!.statusCode).toBe(429);
    expect(res!.body).toContain('Too many attempts');
  });

  it('serves health and not-found responses', async () => {
    const health = await ctx.app.inject({ method: 'GET', url: '/healthz' });
    expect(health.json()).toEqual({ status: 'ok' });
    const page = await ctx.app.inject({ method: 'GET', url: '/nope' });
    expect(page.statusCode).toBe(404);
    expect(page.headers['content-type']).toContain('text/html');
    const api = await ctx.app.inject({ method: 'GET', url: '/api/v1/nope' });
    expect(api.statusCode).toBe(404);
    expect(api.headers['content-type']).toContain('application/problem+json');
  });
});
```

Add the dev dependency that provides the inject response type: `npm i -D light-my-request` (already a Fastify dependency; installing it directly makes the type import explicit).

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/http/login.test.ts`
Expected: FAIL — `src/services.js` / `src/http/app.js` not found.

- [ ] **Step 4: Service container** — `src/services.ts`

```ts
import { ApplicationService } from './apps/applications.js';
import { AuditLog } from './audit/audit.js';
import { LocalAuthenticator } from './auth/local-login.js';
import { LoginRateLimiter } from './auth/rate-limit.js';
import { SessionService } from './auth/sessions.js';
import type { Config } from './config.js';
import { createSecretBox, type SecretBox } from './crypto/secrets.js';
import type { Db } from './db/db.js';
import { EventBus, type DomainEvent } from './events/bus.js';
import { GroupService } from './identity/groups.js';
import { UserService } from './identity/users.js';

export interface Services {
  config: Config;
  db: Db;
  box: SecretBox;
  events: EventBus;
  audit: AuditLog;
  users: UserService;
  groups: GroupService;
  sessions: SessionService;
  limiter: LoginRateLimiter;
  localAuth: LocalAuthenticator;
  apps: ApplicationService;
}

export function createServices(
  config: Config,
  db: Db,
  opts: { onEventError?: (err: unknown, event: DomainEvent) => void } = {},
): Services {
  const box = createSecretBox(config.secretKey);
  const events = new EventBus(opts.onEventError);
  const audit = new AuditLog(db);
  const users = new UserService(db, events);
  const groups = new GroupService(db, events);
  const sessions = new SessionService(db);
  const limiter = new LoginRateLimiter(db);
  const localAuth = new LocalAuthenticator(users, limiter, audit);
  const apps = new ApplicationService(db, box, groups);
  return { config, db, box, events, audit, users, groups, sessions, limiter, localAuth, apps };
}
```

- [ ] **Step 5: HTTP helpers**

`src/http/views.ts`:
```ts
import { fileURLToPath } from 'node:url';
import { Eta } from 'eta';
import type { FastifyReply } from 'fastify';

const eta = new Eta({
  views: fileURLToPath(new URL('../../views/', import.meta.url)),
  cache: process.env.NODE_ENV === 'production',
});

export function renderPage(reply: FastifyReply, template: string, data: Record<string, unknown>): FastifyReply {
  return reply.type('text/html; charset=utf-8').send(eta.render(template, data));
}
```

`src/http/csrf.ts`:
```ts
import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { randomToken } from '../crypto/secrets.js';

export const CSRF_COOKIE = 'authi_csrf';

export function issueCsrfToken(req: FastifyRequest, reply: FastifyReply, config: Config): string {
  const existing = req.cookies[CSRF_COOKIE];
  if (existing && /^[A-Za-z0-9_-]{32}$/.test(existing)) return existing;
  const token = randomToken(24);
  reply.setCookie(CSRF_COOKIE, token, { path: '/', httpOnly: true, sameSite: 'lax', secure: config.secureCookies });
  return token;
}

export function verifyCsrfToken(req: FastifyRequest, submitted: unknown): boolean {
  const expected = req.cookies[CSRF_COOKIE];
  if (!expected || typeof submitted !== 'string' || submitted.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(submitted));
}
```

`src/http/context.ts`:
```ts
import type { CookieSerializeOptions } from '@fastify/cookie';
import type { FastifyRequest } from 'fastify';
import type { RedirectRules } from '../auth/redirects.js';
import { SESSION_COOKIE } from '../auth/sessions.js';
import type { Config } from '../config.js';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';

export async function currentUser(req: FastifyRequest, s: Pick<Services, 'sessions' | 'users'>): Promise<User | null> {
  const session = await s.sessions.validate(req.cookies[SESSION_COOKIE]);
  return session ? s.users.get(session.userId) : null;
}

export function sessionCookieOptions(config: Config, maxAgeSeconds?: number): CookieSerializeOptions {
  return {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    ...(config.cookieDomain ? { domain: config.cookieDomain } : {}),
    ...(maxAgeSeconds !== undefined ? { maxAge: maxAgeSeconds } : {}),
  };
}

export async function redirectRules(s: Pick<Services, 'config' | 'apps'>): Promise<RedirectRules> {
  return {
    issuerUrl: s.config.issuerUrl,
    ...(s.config.cookieDomain ? { cookieDomain: s.config.cookieDomain } : {}),
    allowedHosts: await s.apps.forwardAuthHosts(),
  };
}
```

- [ ] **Step 6: Views**

`views/layout.eta`:
```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><%= it.title %> · Auth.i</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --text:#1d2433; --muted:#5b6475; --accent:#3557d6; --danger:#b42318; --border:#dde1e8; }
@media (prefers-color-scheme: dark) { :root { --bg:#12151b; --card:#1b1f27; --text:#e7eaf0; --muted:#9aa3b2; --accent:#7d97ff; --danger:#ff8a80; --border:#2c323d; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, sans-serif; padding:16px; }
main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--border); border-radius:12px; padding:28px; }
h1 { font-size:1.25rem; margin:0 0 20px; }
label { display:block; font-size:.875rem; color:var(--muted); margin:14px 0 4px; }
input { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:8px; background:transparent; color:inherit; font:inherit; }
button { width:100%; margin-top:20px; padding:10px; border:0; border-radius:8px; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
.error { color:var(--danger); margin:0 0 8px; }
.notice, .muted { color:var(--muted); }
.muted { font-size:.875rem; }
ul.apps { list-style:none; padding:0; margin:0; }
ul.apps a { display:block; padding:10px 0; color:var(--accent); text-decoration:none; border-bottom:1px solid var(--border); }
</style>
</head>
<body><main><%~ it.body %></main></body>
</html>
```

`views/login.eta`:
```html
<% layout('layout') %>
<h1>Sign in to Auth.i</h1>
<% if (it.loggedOut) { %><p class="notice">You have been signed out.</p><% } %>
<% if (it.error) { %><p class="error" role="alert"><%= it.error %></p><% } %>
<form method="post" action="/login">
  <input type="hidden" name="csrf" value="<%= it.csrf %>">
  <input type="hidden" name="rd" value="<%= it.rd %>">
  <label for="identifier">Username or email</label>
  <input id="identifier" name="identifier" value="<%= it.identifier %>" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
```

`views/home.eta`:
```html
<% layout('layout') %>
<h1>Hi <%= it.user.displayName %></h1>
<p class="muted">Signed in as <%= it.user.username %></p>
<% if (it.apps.length) { %>
<ul class="apps">
  <% it.apps.forEach(function (app) { %><li><a href="<%= app.launchUrl %>"><%= app.name %></a></li><% }) %>
</ul>
<% } else { %>
<p class="muted">No applications yet.</p>
<% } %>
<form method="post" action="/logout"><button type="submit">Sign out</button></form>
```

`views/error.eta`:
```html
<% layout('layout') %>
<h1><%= it.title %></h1>
<p><%= it.message %></p>
<p><a href="/">Back to Auth.i</a></p>
```

- [ ] **Step 7: App and login routes**

`src/http/app.ts`:
```ts
import { STATUS_CODES } from 'node:http';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { sql } from 'kysely';
import { ZodError } from 'zod';
import { AppError } from '../errors.js';
import type { Services } from '../services.js';
import { registerLoginRoutes } from './login-routes.js';
import { renderPage } from './views.js';

export interface BuildAppOptions {
  logger?: boolean | { level: string };
}

interface DescribedError {
  status: number;
  title: string;
  detail: string;
  extra?: Record<string, unknown>;
}

function describeError(err: unknown): DescribedError {
  if (err instanceof ZodError) {
    return {
      status: 400,
      title: 'Bad Request',
      detail: 'Validation failed',
      extra: { errors: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
    };
  }
  if (err instanceof AppError) return { status: err.status, title: err.title, detail: err.message };
  const statusCode = (err as FastifyError).statusCode;
  if (statusCode && statusCode >= 400 && statusCode < 500) {
    return { status: statusCode, title: STATUS_CODES[statusCode] ?? 'Error', detail: (err as Error).message };
  }
  return { status: 500, title: 'Internal Server Error', detail: 'An unexpected error occurred' };
}

function sendError(req: FastifyRequest, reply: FastifyReply, e: DescribedError): FastifyReply {
  reply.code(e.status);
  if (req.url.startsWith('/api/')) {
    return reply
      .type('application/problem+json')
      .send({ type: 'about:blank', title: e.title, status: e.status, detail: e.detail, ...e.extra });
  }
  return renderPage(reply, 'error', {
    title: e.title,
    message: e.status >= 500 ? 'Something went wrong. Please try again.' : e.detail,
  });
}

export async function buildApp(s: Services, opts: BuildAppOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: opts.logger ?? false, trustProxy: s.config.trustProxy });
  await app.register(cookie);
  await app.register(formbody);

  app.addHook('onSend', async (_req, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'same-origin');
    reply.header(
      'Content-Security-Policy',
      "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
    );
    if (s.config.secureCookies) reply.header('Strict-Transport-Security', 'max-age=31536000');
    return payload;
  });

  app.setErrorHandler((err, req, reply) => {
    const described = describeError(err);
    if (described.status >= 500) req.log.error({ err }, 'request failed');
    return sendError(req, reply, described);
  });

  app.setNotFoundHandler((req, reply) =>
    sendError(req, reply, { status: 404, title: 'Not Found', detail: 'This page does not exist.' }),
  );

  app.get('/healthz', async () => {
    await sql`SELECT 1`.execute(s.db);
    return { status: 'ok' };
  });

  registerLoginRoutes(app, s);
  return app;
}
```

`src/http/login-routes.ts`:
```ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { canAccess } from '../apps/policy.js';
import { safeRedirectTarget } from '../auth/redirects.js';
import { SESSION_COOKIE } from '../auth/sessions.js';
import type { Services } from '../services.js';
import { currentUser, redirectRules, sessionCookieOptions } from './context.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

type LoginBody = Partial<Record<'csrf' | 'rd' | 'identifier' | 'password', string>>;

export function registerLoginRoutes(app: FastifyInstance, s: Services): void {
  const renderLogin = (
    req: FastifyRequest,
    reply: FastifyReply,
    data: { rd: string; error?: string | null; identifier?: string; loggedOut?: boolean },
  ) =>
    renderPage(reply, 'login', {
      title: 'Sign in',
      csrf: issueCsrfToken(req, reply, s.config),
      rd: data.rd,
      error: data.error ?? null,
      identifier: data.identifier ?? '',
      loggedOut: data.loggedOut ?? false,
    });

  app.get<{ Querystring: { rd?: string; loggedOut?: string } }>('/login', async (req, reply) => {
    const rd = safeRedirectTarget(req.query.rd, await redirectRules(s));
    if (await currentUser(req, s)) return reply.redirect(rd);
    return renderLogin(req, reply, { rd, loggedOut: req.query.loggedOut === '1' });
  });

  app.post<{ Body: LoginBody }>('/login', async (req, reply) => {
    const body = req.body ?? {};
    const rd = safeRedirectTarget(body.rd, await redirectRules(s));
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return renderLogin(req, reply, { rd, error: 'Your sign-in form expired. Please try again.' });
    }
    const identifier = body.identifier ?? '';
    const result = await s.localAuth.authenticate(identifier, body.password ?? '', req.ip);
    if (!result.ok) {
      const limited = result.reason === 'rate_limited';
      reply.code(limited ? 429 : 401);
      return renderLogin(req, reply, {
        rd,
        identifier,
        error: limited ? 'Too many attempts. Try again in a few minutes.' : 'Invalid username or password.',
      });
    }
    const { token } = await s.sessions.create(result.user.id, {
      ip: req.ip,
      ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
    });
    reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions(s.config, s.sessions.ttlSeconds));
    return reply.redirect(rd);
  });

  const logout = async (req: FastifyRequest, reply: FastifyReply) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) {
      const session = await s.sessions.validate(token);
      await s.sessions.destroy(token);
      if (session) await s.audit.record({ actor: { type: 'user', id: session.userId }, action: 'logout', ip: req.ip });
    }
    reply.clearCookie(SESSION_COOKIE, sessionCookieOptions(s.config));
    return reply.redirect('/login?loggedOut=1');
  };
  app.get('/logout', logout);
  app.post('/logout', logout);

  app.get('/', async (req, reply) => {
    const user = await currentUser(req, s);
    if (!user) return reply.redirect('/login');
    const groupIds = await s.groups.groupIdsForUser(user.id);
    const apps = (await s.apps.list()).filter((a) => a.launchUrl && canAccess(user, groupIds, a));
    return renderPage(reply, 'home', { title: 'Your apps', user, apps });
  });
}
```

- [ ] **Step 8: Run tests**

Run: `npx vitest run tests/http/login.test.ts && npm run typecheck`
Expected: 10 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add src/services.ts src/http views tests/helpers/app.ts tests/http package.json package-lock.json
git commit -m "feat: add http app with login, logout and home pages"
```

---
### Task 10: API tokens and admin REST API

**Files:**
- Create: `src/api/tokens.ts`, `src/api/common.ts`, `src/api/plugin.ts`, `src/api/users.ts`, `src/api/groups.ts`, `src/api/applications.ts`, `src/api/api-tokens.ts`, `src/api/audit.ts`
- Modify: `src/services.ts` (add `apiTokens`), `src/http/app.ts` (register API)
- Test: `tests/api/tokens.test.ts`, `tests/api/api.test.ts`

**Interfaces:**
- Consumes: `Services`, all services from Tasks 4–8, `buildApp`, `createTestContext`.
- Produces:
  ```ts
  // api/tokens.ts
  export interface ApiToken { id: string; name: string; createdBy: string | null; createdAt: Date; lastUsedAt: Date | null; expiresAt: Date | null }
  export class ApiTokenService {
    constructor(db: Db);
    create(input: { name: string; createdBy?: string | null; expiresAt?: Date | null }): Promise<{ token: string; apiToken: ApiToken }>;
    verify(token: string): Promise<ApiToken | null>;
    list(): Promise<ApiToken[]>;
    revoke(id: string): Promise<void>;
  }
  // api/common.ts
  export const idParams: z.ZodObject<{ id: z.ZodUUID }>;
  export const usernameSchema: z.ZodString; export const passwordSchema: z.ZodString;
  export function recordAudit(s: Services, req: FastifyRequest, action: string, target?: string | null, details?: Record<string, unknown>): Promise<void>;
  // FastifyRequest is augmented with `actor: Actor | null`
  // api/plugin.ts
  export function registerApi(app: FastifyInstance, s: Services): Promise<void>;   // mounts everything under /api/v1
  // Services gains: apiTokens: ApiTokenService
  ```
- Endpoints (all JSON, Bearer auth):
  | Method & path | Body | Response |
  |---|---|---|
  | `GET /api/v1/users?search&limit&offset` | – | `{ items: User[] }` |
  | `POST /api/v1/users` | create user | `201 User` |
  | `GET /api/v1/users/:id` | – | `User & { groups: Group[] }` |
  | `PATCH /api/v1/users/:id` | partial user | `User` |
  | `DELETE /api/v1/users/:id` | – | `204` |
  | `PUT /api/v1/users/:id/password` | `{ password }` | `204` (also ends the user's sessions) |
  | `DELETE /api/v1/users/:id/sessions` | – | `204` |
  | `GET /api/v1/groups` | – | `{ items: Group[] }` |
  | `POST /api/v1/groups` | `{ name, description? }` | `201 Group` |
  | `GET /api/v1/groups/:id` | – | `Group & { members: User[] }` |
  | `PATCH /api/v1/groups/:id` | `{ name?, description? }` | `Group` |
  | `DELETE /api/v1/groups/:id` | – | `204` |
  | `PUT /api/v1/groups/:id/members/:userId` | – | `204` |
  | `DELETE /api/v1/groups/:id/members/:userId` | – | `204` |
  | `GET /api/v1/applications` | – | `{ items: Application[] }` |
  | `POST /api/v1/applications` | create app | `201 { application, clientSecret }` |
  | `GET /api/v1/applications/:id` | – | `Application` |
  | `PATCH /api/v1/applications/:id` | partial app | `Application` |
  | `DELETE /api/v1/applications/:id` | – | `204` |
  | `POST /api/v1/applications/:id/secret` | – | `{ clientSecret }` |
  | `GET /api/v1/api-tokens` | – | `{ items: ApiToken[] }` |
  | `POST /api/v1/api-tokens` | `{ name, expiresAt? }` | `201 { apiToken, token }` |
  | `DELETE /api/v1/api-tokens/:id` | – | `204` |
  | `GET /api/v1/audit-log?limit&before` | – | `{ items: AuditEntry[] }` |

- [ ] **Step 1: Write the failing tests**

`tests/api/tokens.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiTokenService } from '../../src/api/tokens.js';
import { NotFoundError } from '../../src/errors.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let tokens: ApiTokenService;
beforeEach(async () => {
  t = await createTestDb();
  tokens = new ApiTokenService(t.db);
});
afterEach(() => t.destroy());

describe('ApiTokenService', () => {
  it('creates prefixed tokens, stores only the hash and verifies them', async () => {
    const { token, apiToken } = await tokens.create({ name: 'ci' });
    expect(token).toMatch(/^authi_[A-Za-z0-9_-]{43}$/);
    const raw = await t.db.selectFrom('api_tokens').select('token_hash').executeTakeFirstOrThrow();
    expect(raw.token_hash).not.toContain(token);
    const verified = await tokens.verify(token);
    expect(verified?.id).toBe(apiToken.id);
    expect((await tokens.list())[0]?.lastUsedAt).toBeInstanceOf(Date);
  });

  it('rejects unknown and expired tokens', async () => {
    expect(await tokens.verify('authi_nope')).toBeNull();
    const { token } = await tokens.create({ name: 'old', expiresAt: new Date(Date.now() - 1000) });
    expect(await tokens.verify(token)).toBeNull();
  });

  it('revokes tokens', async () => {
    const { token, apiToken } = await tokens.create({ name: 'ci' });
    await tokens.revoke(apiToken.id);
    expect(await tokens.verify(token)).toBeNull();
    await expect(tokens.revoke(apiToken.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
```

`tests/api/api.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, TEST_PASSWORD, type TestContext } from '../helpers/app.js';

let ctx: TestContext;
let token: string;

beforeEach(async () => {
  ctx = await createTestContext();
  ({ token } = await ctx.services.apiTokens.create({ name: 'test' }));
});
afterEach(() => ctx.close());

function call(method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE', url: string, body?: unknown, auth = token) {
  return ctx.app.inject({
    method,
    url: `/api/v1${url}`,
    headers: { authorization: `Bearer ${auth}` },
    ...(body === undefined ? {} : { payload: body as Record<string, unknown> }),
  });
}

describe('API authentication', () => {
  it('requires a valid bearer token', async () => {
    const none = await ctx.app.inject({ method: 'GET', url: '/api/v1/users' });
    expect(none.statusCode).toBe(401);
    expect(none.headers['content-type']).toContain('application/problem+json');
    expect(none.json()).toMatchObject({ status: 401, title: 'Unauthorized' });
    expect((await call('GET', '/users', undefined, 'authi_wrong')).statusCode).toBe(401);
  });

  it('rejects expired tokens', async () => {
    const expired = await ctx.services.apiTokens.create({ name: 'old', expiresAt: new Date(Date.now() - 1000) });
    expect((await call('GET', '/users', undefined, expired.token)).statusCode).toBe(401);
  });
});

describe('users API', () => {
  it('creates, reads, updates and deletes users', async () => {
    const created = await call('POST', '/users', {
      username: 'alice',
      email: 'alice@example.com',
      displayName: 'Alice',
      password: TEST_PASSWORD,
    });
    expect(created.statusCode).toBe(201);
    const user = created.json();
    expect(user).toMatchObject({ username: 'alice', hasPassword: true });
    expect(JSON.stringify(user)).not.toMatch(/argon2|password_hash|passwordHash/);

    expect((await call('GET', '/users?search=ali')).json().items).toHaveLength(1);
    expect((await call('GET', `/users/${user.id}`)).json()).toMatchObject({ username: 'alice', groups: [] });
    expect((await call('PATCH', `/users/${user.id}`, { displayName: 'Alice L.' })).json().displayName).toBe('Alice L.');
    expect((await call('DELETE', `/users/${user.id}`)).statusCode).toBe(204);
    expect((await call('GET', `/users/${user.id}`)).statusCode).toBe(404);
  });

  it('returns problem details for validation errors and conflicts', async () => {
    const bad = await call('POST', '/users', { username: 'a b', password: 'short' });
    expect(bad.statusCode).toBe(400);
    expect(bad.json().errors.map((e: { path: string }) => e.path).sort()).toEqual(['password', 'username']);
    expect((await call('POST', '/users', { username: 'alice', unknownField: 1 })).statusCode).toBe(400);
    expect((await call('GET', '/users/not-a-uuid')).statusCode).toBe(400);
    await call('POST', '/users', { username: 'alice' });
    const dup = await call('POST', '/users', { username: 'ALICE' });
    expect(dup.statusCode).toBe(409);
    expect(dup.json().title).toBe('Conflict');
  });

  it('sets a password that works for login and ends existing sessions', async () => {
    const user = (await call('POST', '/users', { username: 'alice' })).json();
    const { token: sessionToken } = await ctx.services.sessions.create(user.id);
    expect((await call('PUT', `/users/${user.id}/password`, { password: TEST_PASSWORD })).statusCode).toBe(204);
    expect((await ctx.services.localAuth.authenticate('alice', TEST_PASSWORD, '127.0.0.1')).ok).toBe(true);
    expect(await ctx.services.sessions.validate(sessionToken)).toBeNull();
  });

  it('ends sessions on deactivation and on request', async () => {
    const user = (await call('POST', '/users', { username: 'alice' })).json();
    const a = await ctx.services.sessions.create(user.id);
    expect((await call('DELETE', `/users/${user.id}/sessions`)).statusCode).toBe(204);
    expect(await ctx.services.sessions.validate(a.token)).toBeNull();
    const b = await ctx.services.sessions.create(user.id);
    await call('PATCH', `/users/${user.id}`, { isActive: false });
    const row = await ctx.services.db.selectFrom('sessions').selectAll().execute();
    expect(row).toHaveLength(0);
    expect(await ctx.services.sessions.validate(b.token)).toBeNull();
  });
});

describe('groups API', () => {
  it('manages groups and membership', async () => {
    const user = (await call('POST', '/users', { username: 'alice' })).json();
    const group = (await call('POST', '/groups', { name: 'staff' })).json();
    expect((await call('PUT', `/groups/${group.id}/members/${user.id}`)).statusCode).toBe(204);
    expect((await call('GET', `/groups/${group.id}`)).json().members.map((m: { id: string }) => m.id)).toEqual([user.id]);
    expect((await call('GET', `/users/${user.id}`)).json().groups[0].name).toBe('staff');
    expect((await call('DELETE', `/groups/${group.id}/members/${user.id}`)).statusCode).toBe(204);
    expect((await call('PATCH', `/groups/${group.id}`, { description: 'All staff' })).json().description).toBe('All staff');
    expect((await call('GET', '/groups')).json().items).toHaveLength(1);
    expect((await call('DELETE', `/groups/${group.id}`)).statusCode).toBe(204);
    expect((await call('PUT', `/groups/${group.id}/members/${user.id}`)).statusCode).toBe(404);
  });
});

describe('applications API', () => {
  const demo = { slug: 'demo', name: 'Demo', oidcEnabled: true, redirectUris: ['https://demo.example.com/cb'] };

  it('creates apps, returns the secret once and rotates it', async () => {
    const created = await call('POST', '/applications', demo);
    expect(created.statusCode).toBe(201);
    const { application, clientSecret } = created.json();
    expect(application.clientId).toBe('demo');
    expect(clientSecret).toBeTruthy();
    const fetched = await call('GET', `/applications/${application.id}`);
    expect(fetched.body).not.toContain(clientSecret);
    expect(fetched.body).not.toContain('client_secret');
    const rotated = (await call('POST', `/applications/${application.id}/secret`)).json().clientSecret;
    expect(rotated).not.toBe(clientSecret);
    expect((await call('PATCH', `/applications/${application.id}`, { name: 'Demo 2' })).json().name).toBe('Demo 2');
    expect((await call('GET', '/applications')).json().items).toHaveLength(1);
    expect((await call('DELETE', `/applications/${application.id}`)).statusCode).toBe(204);
  });

  it('validates applications', async () => {
    expect((await call('POST', '/applications', { ...demo, redirectUris: [] })).statusCode).toBe(400);
    expect((await call('POST', '/applications', { ...demo, redirectUris: ['javascript:alert(1)'] })).statusCode).toBe(400);
    expect((await call('POST', '/applications', { ...demo, slug: 'Bad Slug' })).statusCode).toBe(400);
    expect(
      (await call('POST', '/applications', { slug: 'p', name: 'P', forwardAuthEnabled: true, externalHost: 'https://x.example.com' }))
        .statusCode,
    ).toBe(400);
  });
});

describe('api tokens and audit API', () => {
  it('creates, lists and revokes tokens', async () => {
    const created = (await call('POST', '/api-tokens', { name: 'ci' })).json();
    expect(created.token).toMatch(/^authi_/);
    expect((await call('GET', '/users', undefined, created.token)).statusCode).toBe(200);
    const list = await call('GET', '/api-tokens');
    expect(list.body).not.toContain(created.token);
    expect(list.json().items).toHaveLength(2);
    expect((await call('DELETE', `/api-tokens/${created.apiToken.id}`)).statusCode).toBe(204);
    expect((await call('GET', '/users', undefined, created.token)).statusCode).toBe(401);
  });

  it('records admin actions with the token as actor', async () => {
    const user = (await call('POST', '/users', { username: 'alice' })).json();
    const entries = (await call('GET', '/audit-log?limit=10')).json().items;
    expect(entries[0]).toMatchObject({ action: 'user.create', target: user.id, actorType: 'token' });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/api`
Expected: FAIL — modules not found / `apiTokens` missing on services.

- [ ] **Step 3: Implement the token service** — `src/api/tokens.ts`

```ts
import type { Selectable } from 'kysely';
import { hashToken, randomToken } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import type { ApiTokensTable } from '../db/schema.js';
import { NotFoundError } from '../errors.js';
import { isUuid } from '../util.js';

export interface ApiToken {
  id: string;
  name: string;
  createdBy: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
}

function toApiToken(row: Selectable<ApiTokensTable>): ApiToken {
  return {
    id: row.id,
    name: row.name,
    createdBy: row.created_by,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
  };
}

export class ApiTokenService {
  constructor(private readonly db: Db) {}

  async create(input: { name: string; createdBy?: string | null; expiresAt?: Date | null }): Promise<{ token: string; apiToken: ApiToken }> {
    const token = `authi_${randomToken(32)}`;
    const row = await this.db
      .insertInto('api_tokens')
      .values({
        name: input.name,
        token_hash: hashToken(token),
        created_by: input.createdBy ?? null,
        expires_at: input.expiresAt ?? null,
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    return { token, apiToken: toApiToken(row) };
  }

  async verify(token: string): Promise<ApiToken | null> {
    const row = await this.db
      .updateTable('api_tokens')
      .set({ last_used_at: new Date() })
      .where('token_hash', '=', hashToken(token))
      .where((eb) => eb.or([eb('expires_at', 'is', null), eb('expires_at', '>', new Date())]))
      .returningAll()
      .executeTakeFirst();
    return row ? toApiToken(row) : null;
  }

  async list(): Promise<ApiToken[]> {
    return (await this.db.selectFrom('api_tokens').selectAll().orderBy('created_at').execute()).map(toApiToken);
  }

  async revoke(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('api_tokens').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('API token not found');
  }
}
```

Add to `src/services.ts`: `import { ApiTokenService } from './api/tokens.js';`, field `apiTokens: ApiTokenService;` in `Services`, and in `createServices` add `const apiTokens = new ApiTokenService(db);` and include `apiTokens` in the returned object.

- [ ] **Step 4: Shared API helpers** — `src/api/common.ts`

```ts
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Actor } from '../audit/audit.js';
import type { Services } from '../services.js';

declare module 'fastify' {
  interface FastifyRequest {
    actor: Actor | null;
  }
}

export const idParams = z.object({ id: z.uuid() });
export const usernameSchema = z
  .string()
  .regex(/^[a-zA-Z0-9._@-]{2,64}$/, 'use 2-64 letters, digits or . _ @ -');
export const passwordSchema = z.string().min(12, 'must be at least 12 characters').max(256);
export const httpUrl = z.url({ protocol: /^https?$/ });

export async function recordAudit(
  s: Services,
  req: FastifyRequest,
  action: string,
  target: string | null = null,
  details: Record<string, unknown> = {},
): Promise<void> {
  await s.audit.record({ actor: req.actor ?? { type: 'anonymous' }, action, target, details, ip: req.ip });
}
```

- [ ] **Step 5: Route modules**

`src/api/users.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { idParams, passwordSchema, recordAudit, usernameSchema } from './common.js';

const createUserBody = z
  .object({
    username: usernameSchema,
    email: z.email().nullable().optional(),
    displayName: z.string().min(1).max(200).optional(),
    givenName: z.string().max(100).nullable().optional(),
    familyName: z.string().max(100).nullable().optional(),
    isAdmin: z.boolean().optional(),
    isActive: z.boolean().optional(),
    password: passwordSchema.optional(),
  })
  .strict();
const updateUserBody = createUserBody.omit({ password: true }).partial().strict();
const listQuery = z.object({
  search: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export function registerUserRoutes(api: FastifyInstance, s: Services): void {
  api.get('/users', async (req) => ({ items: await s.users.list(listQuery.parse(req.query)) }));

  api.post('/users', async (req, reply) => {
    const user = await s.users.create(createUserBody.parse(req.body));
    await recordAudit(s, req, 'user.create', user.id, { username: user.username });
    return reply.code(201).send(user);
  });

  api.get('/users/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const user = await s.users.get(id);
    if (!user) throw new NotFoundError('User not found');
    return { ...user, groups: await s.groups.groupsForUser(id) };
  });

  api.patch('/users/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const body = updateUserBody.parse(req.body);
    const user = await s.users.update(id, body);
    if (body.isActive === false) await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.update', id, { fields: Object.keys(body) });
    return user;
  });

  api.delete('/users/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.users.delete(id);
    await recordAudit(s, req, 'user.delete', id);
    return reply.code(204).send();
  });

  api.put('/users/:id/password', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    const { password } = z.object({ password: passwordSchema }).strict().parse(req.body);
    await s.users.setPassword(id, password);
    await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.password_set', id);
    return reply.code(204).send();
  });

  api.delete('/users/:id/sessions', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    if (!(await s.users.get(id))) throw new NotFoundError('User not found');
    await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.sessions_revoked', id);
    return reply.code(204).send();
  });
}
```

`src/api/groups.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { idParams, recordAudit } from './common.js';

const groupBody = z.object({ name: z.string().min(1).max(100), description: z.string().max(500).optional() }).strict();
const memberParams = z.object({ id: z.uuid(), userId: z.uuid() });

export function registerGroupRoutes(api: FastifyInstance, s: Services): void {
  api.get('/groups', async () => ({ items: await s.groups.list() }));

  api.post('/groups', async (req, reply) => {
    const group = await s.groups.create(groupBody.parse(req.body));
    await recordAudit(s, req, 'group.create', group.id, { name: group.name });
    return reply.code(201).send(group);
  });

  api.get('/groups/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const group = await s.groups.get(id);
    if (!group) throw new NotFoundError('Group not found');
    return { ...group, members: await s.groups.listMembers(id) };
  });

  api.patch('/groups/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const group = await s.groups.update(id, groupBody.partial().parse(req.body));
    await recordAudit(s, req, 'group.update', id);
    return group;
  });

  api.delete('/groups/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.groups.delete(id);
    await recordAudit(s, req, 'group.delete', id);
    return reply.code(204).send();
  });

  api.put('/groups/:id/members/:userId', async (req, reply) => {
    const { id, userId } = memberParams.parse(req.params);
    await s.groups.addMember(id, userId);
    await recordAudit(s, req, 'group.member_add', id, { userId });
    return reply.code(204).send();
  });

  api.delete('/groups/:id/members/:userId', async (req, reply) => {
    const { id, userId } = memberParams.parse(req.params);
    await s.groups.removeMember(id, userId);
    await recordAudit(s, req, 'group.member_remove', id, { userId });
    return reply.code(204).send();
  });
}
```

`src/api/applications.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { httpUrl, idParams, recordAudit } from './common.js';

const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{1,62}$/, 'use 2-63 lowercase letters, digits or -');
const hostname = z
  .string()
  .max(253)
  .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i, 'must be a bare hostname');
const appFields = {
  name: z.string().min(1).max(200),
  oidcEnabled: z.boolean(),
  forwardAuthEnabled: z.boolean(),
  tokenEndpointAuthMethod: z.enum(['client_secret_basic', 'client_secret_post']),
  redirectUris: z.array(httpUrl).max(20),
  postLogoutRedirectUris: z.array(httpUrl).max(20),
  externalHost: hostname.nullable(),
  allowedGroupIds: z.array(z.uuid()).max(100),
  launchUrl: httpUrl.nullable(),
};
const createBody = z
  .object({ slug, ...appFields })
  .partial()
  .required({ slug: true, name: true })
  .strict();
const updateBody = z.object(appFields).partial().strict();

export function registerApplicationRoutes(api: FastifyInstance, s: Services): void {
  api.get('/applications', async () => ({ items: await s.apps.list() }));

  api.post('/applications', async (req, reply) => {
    const result = await s.apps.create(createBody.parse(req.body));
    await recordAudit(s, req, 'application.create', result.application.id, { slug: result.application.slug });
    return reply.code(201).send(result);
  });

  api.get('/applications/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const app = await s.apps.get(id);
    if (!app) throw new NotFoundError('Application not found');
    return app;
  });

  api.patch('/applications/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const app = await s.apps.update(id, updateBody.parse(req.body));
    await recordAudit(s, req, 'application.update', id);
    return app;
  });

  api.delete('/applications/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.apps.delete(id);
    await recordAudit(s, req, 'application.delete', id);
    return reply.code(204).send();
  });

  api.post('/applications/:id/secret', async (req) => {
    const { id } = idParams.parse(req.params);
    const clientSecret = await s.apps.rotateSecret(id);
    await recordAudit(s, req, 'application.secret_rotate', id);
    return { clientSecret };
  });
}
```

`src/api/api-tokens.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Services } from '../services.js';
import { idParams, recordAudit } from './common.js';

const createBody = z.object({ name: z.string().min(1).max(100), expiresAt: z.iso.datetime().optional() }).strict();

export function registerApiTokenRoutes(api: FastifyInstance, s: Services): void {
  api.get('/api-tokens', async () => ({ items: await s.apiTokens.list() }));

  api.post('/api-tokens', async (req, reply) => {
    const body = createBody.parse(req.body);
    const created = await s.apiTokens.create({
      name: body.name,
      createdBy: req.actor?.type === 'user' ? req.actor.id : null,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
    });
    await recordAudit(s, req, 'api_token.create', created.apiToken.id, { name: body.name });
    return reply.code(201).send(created);
  });

  api.delete('/api-tokens/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.apiTokens.revoke(id);
    await recordAudit(s, req, 'api_token.revoke', id);
    return reply.code(204).send();
  });
}
```

`src/api/audit.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Services } from '../services.js';

const query = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
  before: z.string().regex(/^\d+$/).optional(),
});

export function registerAuditRoutes(api: FastifyInstance, s: Services): void {
  api.get('/audit-log', async (req) => ({ items: await s.audit.list(query.parse(req.query)) }));
}
```

`src/api/plugin.ts`:
```ts
import type { FastifyInstance } from 'fastify';
import { UnauthorizedError } from '../errors.js';
import type { Services } from '../services.js';
import { registerApiTokenRoutes } from './api-tokens.js';
import { registerApplicationRoutes } from './applications.js';
import { registerAuditRoutes } from './audit.js';
import './common.js';
import { registerGroupRoutes } from './groups.js';
import { registerUserRoutes } from './users.js';

export async function registerApi(app: FastifyInstance, s: Services): Promise<void> {
  await app.register(
    async (api) => {
      api.decorateRequest('actor', null);
      api.addHook('onRequest', async (req) => {
        const match = req.headers.authorization?.match(/^Bearer\s+(\S+)$/i);
        const token = match?.[1] ? await s.apiTokens.verify(match[1]) : null;
        if (!token) throw new UnauthorizedError();
        req.actor = { type: 'token', id: token.id };
      });
      registerUserRoutes(api, s);
      registerGroupRoutes(api, s);
      registerApplicationRoutes(api, s);
      registerApiTokenRoutes(api, s);
      registerAuditRoutes(api, s);
    },
    { prefix: '/api/v1' },
  );
}
```

In `src/http/app.ts`: add `import { registerApi } from '../api/plugin.js';` and after `registerLoginRoutes(app, s);` add `await registerApi(app, s);`.

- [ ] **Step 6: Run tests**

Run: `npx vitest run tests/api tests/http && npm run typecheck`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src/api src/services.ts src/http/app.ts tests/api
git commit -m "feat: add admin REST API with bearer API tokens"
```

---
### Task 11: Signing keys and OIDC storage adapter

**Files:**
- Create: `src/oidc/keys.ts`, `src/oidc/adapter.ts`
- Modify: `src/services.ts` (add `keys`)
- Test: `tests/oidc/keys.test.ts`, `tests/oidc/adapter.test.ts`

**Interfaces:**
- Consumes: `Db`, `SecretBox`.
- Produces:
  ```ts
  // keys.ts
  export type SigningJwk = JsonWebKey & { kid: string; alg: 'RS256' | 'ES256'; use: 'sig' };
  export const RETIRED_KEY_GRACE_MS: number;   // 24h
  export class SigningKeyService {
    constructor(db: Db, box: SecretBox);
    ensureKeys(): Promise<void>;               // one active RS256 + one active ES256, idempotent
    rotate(): Promise<void>;                   // retire active keys, create new ones
    getSigningJwks(): Promise<SigningJwk[]>;   // active first, then retired within grace
  }
  // adapter.ts
  export class PostgresAdapter implements Adapter {
    constructor(name: string, db: Db, loadClient: (clientId: string) => Promise<AdapterPayload | undefined>);
  }
  export function purgeExpiredOidcPayloads(db: Db): Promise<number>;
  // Services gains: keys: SigningKeyService
  ```

- [ ] **Step 1: Write the failing tests**

`tests/oidc/keys.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSecretBox } from '../../src/crypto/secrets.js';
import { RETIRED_KEY_GRACE_MS, SigningKeyService } from '../../src/oidc/keys.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let keys: SigningKeyService;
beforeEach(async () => {
  t = await createTestDb();
  keys = new SigningKeyService(t.db, createSecretBox(Buffer.alloc(32, 5)));
});
afterEach(() => t.destroy());

describe('SigningKeyService', () => {
  it('creates one RS256 and one ES256 key, idempotently', async () => {
    await keys.ensureKeys();
    await keys.ensureKeys();
    const jwks = await keys.getSigningJwks();
    expect(jwks.map((k) => k.alg).sort()).toEqual(['ES256', 'RS256']);
    for (const k of jwks) {
      expect(k).toMatchObject({ use: 'sig' });
      expect(k.kid).toBeTruthy();
      expect(k.d).toBeTruthy(); // private part present for signing
    }
  });

  it('stores keys encrypted', async () => {
    await keys.ensureKeys();
    const rows = await t.db.selectFrom('signing_keys').select('private_jwk_enc').execute();
    for (const r of rows) expect(r.private_jwk_enc).not.toContain('"d"');
  });

  it('rotates keys, keeping retired keys published during the grace period', async () => {
    await keys.ensureKeys();
    const before = (await keys.getSigningJwks()).map((k) => k.kid);
    await keys.rotate();
    const after = await keys.getSigningJwks();
    expect(after).toHaveLength(4);
    expect(before).not.toContain(after[0]!.kid);
    expect(before).not.toContain(after[1]!.kid);
    expect(after.slice(2).map((k) => k.kid).sort()).toEqual([...before].sort());

    await t.db
      .updateTable('signing_keys')
      .set({ retired_at: new Date(Date.now() - RETIRED_KEY_GRACE_MS - 1000) })
      .where('status', '=', 'retired')
      .execute();
    expect(await keys.getSigningJwks()).toHaveLength(2);
  });
});
```

`tests/oidc/adapter.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PostgresAdapter, purgeExpiredOidcPayloads } from '../../src/oidc/adapter.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
const noClient = async () => undefined;
beforeEach(async () => {
  t = await createTestDb();
});
afterEach(() => t.destroy());

describe('PostgresAdapter', () => {
  it('upserts and finds payloads by id, uid and user code', async () => {
    const a = new PostgresAdapter('Interaction', t.db, noClient);
    await a.upsert('i1', { uid: 'u1', userCode: 'UC1', returnTo: '/x' }, 60);
    expect(await a.find('i1')).toMatchObject({ uid: 'u1', returnTo: '/x' });
    expect(await a.findByUid('u1')).toMatchObject({ returnTo: '/x' });
    expect(await a.findByUserCode('UC1')).toMatchObject({ returnTo: '/x' });
    await a.upsert('i1', { uid: 'u1', returnTo: '/y' }, 60);
    expect(await a.find('i1')).toMatchObject({ returnTo: '/y' });
  });

  it('separates models by name', async () => {
    await new PostgresAdapter('Session', t.db, noClient).upsert('same', { kind: 'Session' }, 60);
    expect(await new PostgresAdapter('Grant', t.db, noClient).find('same')).toBeUndefined();
  });

  it('hides expired payloads and purges them', async () => {
    const a = new PostgresAdapter('AccessToken', t.db, noClient);
    await a.upsert('old', { grantId: 'g' }, -1);
    expect(await a.find('old')).toBeUndefined();
    expect(await purgeExpiredOidcPayloads(t.db)).toBe(1);
  });

  it('marks payloads consumed', async () => {
    const a = new PostgresAdapter('AuthorizationCode', t.db, noClient);
    await a.upsert('c1', { grantId: 'g' }, 60);
    await a.consume('c1');
    expect(await a.find('c1')).toMatchObject({ consumed: true });
  });

  it('destroys and revokes by grant across models', async () => {
    const codes = new PostgresAdapter('AuthorizationCode', t.db, noClient);
    const refresh = new PostgresAdapter('RefreshToken', t.db, noClient);
    await codes.upsert('c1', { grantId: 'g1' }, 60);
    await refresh.upsert('r1', { grantId: 'g1' }, 60);
    await refresh.upsert('r2', { grantId: 'g2' }, 60);
    await codes.revokeByGrantId('g1');
    expect(await codes.find('c1')).toBeUndefined();
    expect(await refresh.find('r1')).toBeUndefined();
    expect(await refresh.find('r2')).toBeDefined();
    await refresh.destroy('r2');
    expect(await refresh.find('r2')).toBeUndefined();
  });

  it('loads clients through the client loader', async () => {
    const a = new PostgresAdapter('Client', t.db, async (id) => (id === 'demo' ? { client_id: 'demo' } : undefined));
    expect(await a.find('demo')).toEqual({ client_id: 'demo' });
    expect(await a.find('other')).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/oidc/keys.test.ts tests/oidc/adapter.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement**

`src/oidc/keys.ts`:
```ts
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import type { SecretBox } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';

export type SigningJwk = JsonWebKey & { kid: string; alg: 'RS256' | 'ES256'; use: 'sig' };

const ALGS = ['RS256', 'ES256'] as const;
export const RETIRED_KEY_GRACE_MS = 24 * 60 * 60 * 1000;

function generateJwk(alg: (typeof ALGS)[number]): SigningJwk {
  const { privateKey } =
    alg === 'RS256'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), alg, use: 'sig' };
}

export class SigningKeyService {
  constructor(
    private readonly db: Db,
    private readonly box: SecretBox,
  ) {}

  async ensureKeys(): Promise<void> {
    const active = await this.db.selectFrom('signing_keys').select('alg').where('status', '=', 'active').execute();
    const have = new Set(active.map((r) => r.alg));
    for (const alg of ALGS) {
      if (!have.has(alg)) await this.insert(this.db, alg);
    }
  }

  async rotate(): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await trx
        .updateTable('signing_keys')
        .set({ status: 'retired', retired_at: new Date() })
        .where('status', '=', 'active')
        .execute();
      for (const alg of ALGS) await this.insert(trx, alg);
    });
  }

  async getSigningJwks(): Promise<SigningJwk[]> {
    const rows = await this.db
      .selectFrom('signing_keys')
      .select('private_jwk_enc')
      .where((eb) =>
        eb.or([
          eb('status', '=', 'active'),
          eb('retired_at', '>', new Date(Date.now() - RETIRED_KEY_GRACE_MS)),
        ]),
      )
      .orderBy('status', 'asc') // 'active' sorts before 'retired'
      .orderBy('created_at', 'desc')
      .execute();
    return rows.map((r) => JSON.parse(this.box.decrypt(r.private_jwk_enc)) as SigningJwk);
  }

  private async insert(db: Db, alg: (typeof ALGS)[number]): Promise<void> {
    const jwk = generateJwk(alg);
    await db
      .insertInto('signing_keys')
      .values({ kid: jwk.kid, alg, private_jwk_enc: this.box.encrypt(JSON.stringify(jwk)), status: 'active', retired_at: null })
      .execute();
  }
}
```

Note: `trx` is a `Transaction<Database>`, which is a subclass of `Kysely<Database>`, so it satisfies `Db`.

`src/oidc/adapter.ts`:
```ts
import type { Adapter, AdapterPayload } from 'oidc-provider';
import type { Db } from '../db/db.js';

export class PostgresAdapter implements Adapter {
  constructor(
    private readonly name: string,
    private readonly db: Db,
    private readonly loadClient: (clientId: string) => Promise<AdapterPayload | undefined>,
  ) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    const values = {
      payload: JSON.stringify(payload),
      grant_id: typeof payload.grantId === 'string' ? payload.grantId : null,
      user_code: typeof payload.userCode === 'string' ? payload.userCode : null,
      uid: typeof payload.uid === 'string' ? payload.uid : null,
      expires_at: expiresIn === undefined ? null : new Date(Date.now() + expiresIn * 1000),
    };
    await this.db
      .insertInto('oidc_payloads')
      .values({ id, type: this.name, consumed_at: null, ...values })
      .onConflict((oc) => oc.columns(['type', 'id']).doUpdateSet(values))
      .execute();
  }

  find(id: string): Promise<AdapterPayload | undefined> {
    if (this.name === 'Client') return this.loadClient(id);
    return this.findBy('id', id);
  }

  findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.findBy('uid', uid);
  }

  findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.findBy('user_code', userCode);
  }

  async consume(id: string): Promise<void> {
    await this.db
      .updateTable('oidc_payloads')
      .set({ consumed_at: new Date() })
      .where('type', '=', this.name)
      .where('id', '=', id)
      .execute();
  }

  async destroy(id: string): Promise<void> {
    await this.db.deleteFrom('oidc_payloads').where('type', '=', this.name).where('id', '=', id).execute();
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.db.deleteFrom('oidc_payloads').where('grant_id', '=', grantId).execute();
  }

  private async findBy(column: 'id' | 'uid' | 'user_code', value: string): Promise<AdapterPayload | undefined> {
    const row = await this.db
      .selectFrom('oidc_payloads')
      .select(['payload', 'consumed_at', 'expires_at'])
      .where('type', '=', this.name)
      .where(column, '=', value)
      .executeTakeFirst();
    if (!row || (row.expires_at && row.expires_at <= new Date())) return undefined;
    return { ...(row.payload as AdapterPayload), ...(row.consumed_at ? { consumed: true } : {}) };
  }
}

export async function purgeExpiredOidcPayloads(db: Db): Promise<number> {
  const result = await db.deleteFrom('oidc_payloads').where('expires_at', '<=', new Date()).executeTakeFirst();
  return Number(result.numDeletedRows);
}
```

Add to `src/services.ts`: `import { SigningKeyService } from './oidc/keys.js';`, field `keys: SigningKeyService;`, `const keys = new SigningKeyService(db, box);`, include `keys` in the returned object.

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/oidc && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oidc src/services.ts tests/oidc
git commit -m "feat: add encrypted signing keys and postgres oidc adapter"
```

---
### Task 12: OIDC provider and login interactions

**Files:**
- Create: `src/oidc/provider.ts`, `src/oidc/holder.ts`, `src/http/interaction-routes.ts`, `src/api/keys.ts`
- Create: `tests/helpers/net.ts`, `tests/helpers/browser.ts`
- Modify: `src/services.ts` (add `oidc`, `startServices`), `src/http/app.ts` (mount provider, interaction routes, OIDC error mapping), `src/api/plugin.ts` (keys route), `tests/helpers/app.ts` (start services, listening context)
- Test: `tests/oidc/flow.test.ts`

**Interfaces:**
- Consumes: `Services` (Tasks 9–11), `canAccess`, `SESSION_COOKIE`, `deriveKey`, `PostgresAdapter`, `SigningKeyService`, `currentUser`, `recordAudit`.
- Produces:
  ```ts
  // oidc/provider.ts
  export interface OidcDeps { config: Config; db: Db; users: UserService; groups: GroupService; apps: ApplicationService;
    sessions: SessionService; keys: SigningKeyService; audit: AuditLog }
  export function createOidcProvider(d: OidcDeps): Promise<Provider>;
  // oidc/holder.ts
  export class OidcProviderHolder {
    constructor(factory: () => Promise<Provider>);
    load(): Promise<void>;                                   // (re)builds the provider, e.g. after key rotation
    readonly provider: Provider;                              // throws if not loaded
    handle(req: IncomingMessage, res: ServerResponse): void;  // Koa callback of the current provider
  }
  // services.ts
  // Services gains: oidc: OidcProviderHolder
  export function startServices(s: Services): Promise<void>;  // ensureKeys + oidc.load
  // tests/helpers/net.ts
  export function getFreePort(): Promise<number>;
  // tests/helpers/browser.ts
  export interface Page { url: URL; response: Response | null }
  export class TestBrowser {
    readonly jar: Map<string, string>;
    fetch(url: string, init?: { form?: Record<string, string> }): Promise<Response>;
    navigate(url: string, stop?: (u: URL) => boolean): Promise<Page>;
    signIn(page: Page, identifier: string, password: string, stop?: (u: URL) => boolean): Promise<Page>;
  }
  // tests/helpers/app.ts gains
  export interface ListeningContext extends TestContext { baseUrl: string }
  export function createListeningContext(): Promise<ListeningContext>;
  ```
- Routes: `/oidc/*` (oidc-provider: discovery at `/oidc/.well-known/openid-configuration`, `/oidc/auth`, `/oidc/token`, `/oidc/me`, `/oidc/jwks`, `/oidc/session/end`, `/oidc/token/revocation`, `/oidc/token/introspection`), `GET /interaction/:uid`, `POST /api/v1/keys/rotate`.

Behaviour summary (the tests below pin each line):
- The OIDC `login` prompt also fires when the Auth.i session cookie is missing or belongs to another user, so signing out of Auth.i signs the user out of OIDC as well.
- `/interaction/:uid` sends users without a session to `/login?rd=/interaction/<uid>`; signed-in users are checked against the app policy and either get `access_denied` or an auto-granted consent (all apps are first-party).
- `findAccount` returns nothing for inactive users or users who lost access to the requesting client, which makes refresh-token grants fail immediately.
- Refresh tokens are issued whenever the client allows the `refresh_token` grant (no `offline_access` + `prompt=consent` dance).
- ID tokens carry the same profile/email/groups claims as userinfo (`conformIdTokenClaims: false`), because many apps only read the ID token.

- [ ] **Step 1: Test helpers**

`tests/helpers/net.ts`:
```ts
import { createServer, type AddressInfo } from 'node:net';

export function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}
```

`tests/helpers/browser.ts`:
```ts
export interface Page {
  url: URL;
  response: Response | null;
}

const decodeHtml = (s: string) =>
  s.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

/** Minimal cookie-keeping browser for one host. Ignores cookie domain/path, which is fine for tests on 127.0.0.1. */
export class TestBrowser {
  readonly jar = new Map<string, string>();

  async fetch(url: string, init: { form?: Record<string, string> } = {}): Promise<Response> {
    const headers: Record<string, string> = {};
    if (this.jar.size) headers.cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    let body: string | undefined;
    if (init.form) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(init.form).toString();
    }
    const res = await fetch(url, { method: init.form ? 'POST' : 'GET', headers, body, redirect: 'manual' });
    for (const raw of res.headers.getSetCookie()) {
      const [pair = '', ...attrs] = raw.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
      if (expired || value === '') this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }

  /** Follows redirects until `stop` matches the next URL or a non-redirect response arrives. */
  async navigate(url: string, stop: (u: URL) => boolean = () => false): Promise<Page> {
    let current = new URL(url);
    for (let hop = 0; hop < 20; hop++) {
      if (stop(current)) return { url: current, response: null };
      const res = await this.fetch(current.href);
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location) {
        current = new URL(location, current);
        continue;
      }
      return { url: current, response: res };
    }
    throw new Error('Too many redirects');
  }

  /** Submits the Auth.i login form shown on `page` and follows the resulting redirects. */
  async signIn(page: Page, identifier: string, password: string, stop: (u: URL) => boolean = () => false): Promise<Page> {
    const html = await page.response!.text();
    const field = (name: string) => decodeHtml(html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? '');
    const res = await this.fetch(new URL('/login', page.url).href, {
      form: { csrf: field('csrf'), rd: field('rd'), identifier, password },
    });
    const location = res.headers.get('location');
    if (!location) return { url: page.url, response: res };
    return this.navigate(new URL(location, page.url).href, stop);
  }
}
```

Replace `tests/helpers/app.ts` `createTestContext` and add `createListeningContext` (keep `TEST_PASSWORD`, `testConfig`, `TestContext` unchanged):
```ts
import type { FastifyInstance } from 'fastify';
import type { Config } from '../../src/config.js';
import { buildApp } from '../../src/http/app.js';
import { createServices, startServices, type Services } from '../../src/services.js';
import { createTestDb } from './db.js';
import { getFreePort } from './net.js';

// ... TEST_PASSWORD, testConfig, TestContext unchanged ...

export async function createTestContext(overrides: Partial<Config> = {}): Promise<TestContext> {
  const tdb = await createTestDb();
  const services = createServices(testConfig({ databaseUrl: tdb.url, ...overrides }), tdb.db);
  await startServices(services);
  const app = await buildApp(services);
  return {
    services,
    app,
    async close() {
      await app.close();
      await tdb.destroy();
    },
  };
}

export interface ListeningContext extends TestContext {
  baseUrl: string;
}

export async function createListeningContext(): Promise<ListeningContext> {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const ctx = await createTestContext({ issuerUrl: baseUrl, port });
  await ctx.app.listen({ port, host: '127.0.0.1' });
  return { ...ctx, baseUrl };
}
```

- [ ] **Step 2: Write the failing test** — `tests/oidc/flow.test.ts`

```ts
import * as client from 'openid-client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { User } from '../../src/identity/users.js';
import type { Group } from '../../src/identity/groups.js';
import { createListeningContext, TEST_PASSWORD, type ListeningContext } from '../helpers/app.js';
import { TestBrowser, type Page } from '../helpers/browser.js';

const REDIRECT = 'http://rp.test/cb';
const isCallback = (u: URL) => u.host === 'rp.test';

let ctx: ListeningContext;
let alice: User;
let staff: Group;
let secret: string;

beforeEach(async () => {
  ctx = await createListeningContext();
  const s = ctx.services;
  alice = await s.users.create({
    username: 'alice',
    email: 'alice@example.test',
    displayName: 'Alice Liddell',
    givenName: 'Alice',
    familyName: 'Liddell',
    password: TEST_PASSWORD,
  });
  staff = await s.groups.create({ name: 'staff' });
  await s.groups.addMember(staff.id, alice.id);
  ({ clientSecret: secret } = await s.apps.create({
    slug: 'demo',
    name: 'Demo',
    oidcEnabled: true,
    redirectUris: [REDIRECT],
    allowedGroupIds: [staff.id],
  }));
});
afterEach(() => ctx.close());

function discover() {
  return client.discovery(new URL(`${ctx.baseUrl}/oidc`), 'demo', secret, undefined, {
    execute: [client.allowInsecureRequests],
  });
}

async function authorize(browser: TestBrowser, config: client.Configuration, extra: Record<string, string> = {}) {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT,
    scope: 'openid profile email groups',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    ...extra,
  });
  const page: Page = await browser.navigate(url.href, isCallback);
  return { verifier, state, page };
}

async function signInAndExchange(browser: TestBrowser, config: client.Configuration) {
  const { verifier, state, page } = await authorize(browser, config);
  expect(page.url.pathname).toBe('/login');
  const done = await browser.signIn(page, 'alice', TEST_PASSWORD, isCallback);
  expect(isCallback(done.url)).toBe(true);
  return client.authorizationCodeGrant(config, done.url, { pkceCodeVerifier: verifier, expectedState: state });
}

describe('OIDC provider', () => {
  it('publishes discovery and a JWKS with RS256 and ES256 keys', async () => {
    const config = await discover();
    expect(config.serverMetadata().issuer).toBe(`${ctx.baseUrl}/oidc`);
    const jwks = await (await fetch(config.serverMetadata().jwks_uri!)).json();
    expect(jwks.keys.map((k: { alg: string }) => k.alg).sort()).toEqual(['ES256', 'RS256']);
    expect(jwks.keys.every((k: { d?: string }) => k.d === undefined)).toBe(true);
  });

  it('signs in through the Auth.i login page and issues tokens with profile, email and groups', async () => {
    const config = await discover();
    const tokens = await signInAndExchange(new TestBrowser(), config);
    const claims = tokens.claims()!;
    expect(claims).toMatchObject({
      sub: alice.id,
      preferred_username: 'alice',
      name: 'Alice Liddell',
      given_name: 'Alice',
      family_name: 'Liddell',
      email: 'alice@example.test',
      email_verified: true,
      groups: ['staff'],
    });
    expect(tokens.refresh_token).toBeTruthy();
    const info = await client.fetchUserInfo(config, tokens.access_token, alice.id);
    expect(info).toMatchObject({ email: 'alice@example.test', groups: ['staff'] });
  });

  it('reuses the Auth.i session for the next authorization without showing the form', async () => {
    const config = await discover();
    const browser = new TestBrowser();
    await signInAndExchange(browser, config);
    const { page } = await authorize(browser, config);
    expect(isCallback(page.url)).toBe(true);
    expect(page.url.searchParams.get('code')).toBeTruthy();
  });

  it('returns access_denied for users outside the allowed groups', async () => {
    await ctx.services.groups.removeMember(staff.id, alice.id);
    const config = await discover();
    const browser = new TestBrowser();
    const { page } = await authorize(browser, config);
    const done = await browser.signIn(page, 'alice', TEST_PASSWORD, isCallback);
    expect(done.url.searchParams.get('error')).toBe('access_denied');
  });

  it('stops refreshing once the user loses access to the app', async () => {
    const config = await discover();
    const tokens = await signInAndExchange(new TestBrowser(), config);
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    await ctx.services.groups.removeMember(staff.id, alice.id);
    await expect(client.refreshTokenGrant(config, refreshed.refresh_token ?? tokens.refresh_token!)).rejects.toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('stops refreshing once the user is deactivated', async () => {
    const config = await discover();
    const tokens = await signInAndExchange(new TestBrowser(), config);
    await ctx.services.users.update(alice.id, { isActive: false });
    await expect(client.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('answers prompt=none without a session with login_required', async () => {
    const config = await discover();
    const { page } = await authorize(new TestBrowser(), config, { prompt: 'none' });
    expect(page.url.searchParams.get('error')).toBe('login_required');
  });

  it('requires a fresh login after signing out of Auth.i', async () => {
    const config = await discover();
    const browser = new TestBrowser();
    await signInAndExchange(browser, config);
    await browser.fetch(`${ctx.baseUrl}/logout`);
    const { page } = await authorize(browser, config);
    expect(page.url.pathname).toBe('/login');
  });

  it('shows a friendly page for an expired interaction', async () => {
    const res = await fetch(`${ctx.baseUrl}/interaction/does-not-exist`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('expired');
  });

  it('rotates signing keys through the API and keeps old keys published', async () => {
    const { token } = await ctx.services.apiTokens.create({ name: 'test' });
    const res = await fetch(`${ctx.baseUrl}/api/v1/keys/rotate`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(204);
    const jwks = await (await fetch(`${ctx.baseUrl}/oidc/jwks`)).json();
    expect(jwks.keys).toHaveLength(4);
    const tokens = await signInAndExchange(new TestBrowser(), await discover());
    expect(tokens.claims()?.sub).toBe(alice.id);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/oidc/flow.test.ts`
Expected: FAIL — `startServices` not exported from `src/services.js`.

- [ ] **Step 4: Provider factory** — `src/oidc/provider.ts`

```ts
import Provider, { interactionPolicy, type Configuration, type FindAccount, type KoaContextWithOIDC } from 'oidc-provider';
import type { ApplicationService } from '../apps/applications.js';
import { canAccess } from '../apps/policy.js';
import type { AuditLog } from '../audit/audit.js';
import { SESSION_COOKIE, type SessionService } from '../auth/sessions.js';
import type { Config } from '../config.js';
import { deriveKey } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import type { GroupService } from '../identity/groups.js';
import type { UserService } from '../identity/users.js';
import { PostgresAdapter } from './adapter.js';
import type { SigningKeyService } from './keys.js';

export interface OidcDeps {
  config: Config;
  db: Db;
  users: UserService;
  groups: GroupService;
  apps: ApplicationService;
  sessions: SessionService;
  keys: SigningKeyService;
  audit: AuditLog;
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} · Auth.i</title></head><body style="font:16px/1.5 system-ui,sans-serif;max-width:420px;margin:15vh auto;padding:0 16px">${body}</body></html>`;
}

export async function createOidcProvider(d: OidcDeps): Promise<Provider> {
  const policy = interactionPolicy.base();
  policy.get('login')!.checks.add(
    new interactionPolicy.Check(
      'authi_session',
      'Auth.i session is missing or belongs to another user',
      async (ctx: KoaContextWithOIDC) => {
        const token = ctx.cookies.get(SESSION_COOKIE, { signed: false });
        const session = await d.sessions.validate(token);
        return session && session.userId === ctx.oidc.session?.accountId
          ? interactionPolicy.Check.NO_NEED_TO_PROMPT
          : interactionPolicy.Check.REQUEST_PROMPT;
      },
    ),
  );

  const findAccount: FindAccount = async (ctx, sub) => {
    const user = await d.users.get(sub);
    if (!user || !user.isActive) return undefined;
    const clientId = ctx.oidc?.client?.clientId;
    if (clientId) {
      const app = await d.apps.getByClientId(clientId);
      if (!app || !canAccess(user, await d.groups.groupIdsForUser(user.id), app)) return undefined;
    }
    return {
      accountId: user.id,
      async claims() {
        return {
          sub: user.id,
          name: user.displayName,
          preferred_username: user.username,
          ...(user.givenName ? { given_name: user.givenName } : {}),
          ...(user.familyName ? { family_name: user.familyName } : {}),
          ...(user.email ? { email: user.email, email_verified: true } : {}),
          groups: await d.users.groupNames(user.id),
        };
      },
    };
  };

  const configuration: Configuration = {
    adapter: (name: string) => new PostgresAdapter(name, d.db, (id) => d.apps.oidcClientMetadata(id)),
    jwks: { keys: (await d.keys.getSigningJwks()) as NonNullable<Configuration['jwks']>['keys'] },
    cookies: { keys: [deriveKey(d.config.secretKey, 'oidc-cookies').toString('base64url')] },
    findAccount,
    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name', 'preferred_username'],
      email: ['email', 'email_verified'],
      groups: ['groups'],
    },
    scopes: ['openid', 'offline_access', 'profile', 'email', 'groups'],
    conformIdTokenClaims: false,
    issueRefreshToken: async (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      introspection: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        async logoutSource(ctx, form) {
          ctx.body = page(
            'Signing out',
            `${form}<input type="hidden" form="op.logoutForm" name="logout" value="yes"><p>Signing out…</p><noscript><button form="op.logoutForm" type="submit">Continue</button></noscript><script>document.forms[0].submit()</script>`,
          );
        },
        async postLogoutSuccessSource(ctx) {
          ctx.body = page('Signed out', '<h1>You are signed out</h1><p><a href="/login">Sign in again</a></p>');
        },
      },
    },
    interactions: { policy, url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    ttl: {
      AccessToken: 3600,
      AuthorizationCode: 60,
      ClientCredentials: 600,
      IdToken: 3600,
      Interaction: 600,
      Grant: 14 * 24 * 3600,
      RefreshToken: 14 * 24 * 3600,
      Session: 14 * 24 * 3600,
    },
    async renderError(ctx, out) {
      ctx.type = 'html';
      ctx.body = page(
        'Error',
        `<h1>Something went wrong</h1><p>${escapeHtml(String(out.error_description ?? out.error))}</p>`,
      );
    },
  };

  const provider = new Provider(`${d.config.issuerUrl}/oidc`, configuration);
  provider.proxy = true;
  provider.on('end_session.success', (ctx: KoaContextWithOIDC) => {
    const token = ctx.cookies.get(SESSION_COOKIE, { signed: false });
    if (token) void d.sessions.destroy(token).catch(() => {});
  });
  return provider;
}
```

Note: Koa's `ctx.cookies.get` defaults to signed reads once cookie keys are configured, so the explicit `{ signed: false }` is required to read the plain `authi_session` cookie.

`src/oidc/holder.ts`:
```ts
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';

export class OidcProviderHolder {
  #provider: Provider | undefined;
  #handler: ((req: IncomingMessage, res: ServerResponse) => unknown) | undefined;

  constructor(private readonly factory: () => Promise<Provider>) {}

  async load(): Promise<void> {
    const provider = await this.factory();
    this.#provider = provider;
    this.#handler = provider.callback();
  }

  get provider(): Provider {
    if (!this.#provider) throw new Error('OIDC provider not loaded; call startServices() first');
    return this.#provider;
  }

  handle(req: IncomingMessage, res: ServerResponse): void {
    if (!this.#handler) throw new Error('OIDC provider not loaded; call startServices() first');
    void this.#handler(req, res);
  }
}
```

- [ ] **Step 5: Wire services** — `src/services.ts`

Add imports `import { OidcProviderHolder } from './oidc/holder.js';` and `import { createOidcProvider } from './oidc/provider.js';`, add field `oidc: OidcProviderHolder;` to `Services`, then in `createServices` before the `return`:
```ts
  const oidc = new OidcProviderHolder(() =>
    createOidcProvider({ config, db, users, groups, apps, sessions, keys, audit }),
  );
```
include `oidc` in the returned object, and append:
```ts
export async function startServices(s: Services): Promise<void> {
  await s.keys.ensureKeys();
  await s.oidc.load();
}
```

- [ ] **Step 6: Interaction route** — `src/http/interaction-routes.ts`

```ts
import type { FastifyInstance } from 'fastify';
import type { InteractionResults } from 'oidc-provider';
import { canAccess } from '../apps/policy.js';
import type { Services } from '../services.js';
import { currentUser } from './context.js';

interface PromptDetails {
  missingOIDCClaims?: string[];
  missingResourceScopes?: Record<string, string[]>;
}

export function registerInteractionRoutes(app: FastifyInstance, s: Services): void {
  app.get<{ Params: { uid: string } }>('/interaction/:uid', async (req, reply) => {
    const provider = s.oidc.provider;
    const details = await provider.interactionDetails(req.raw, reply.raw);
    const user = await currentUser(req, s);
    if (!user) {
      return reply.redirect(`/login?rd=${encodeURIComponent(`/interaction/${details.uid}`)}`);
    }

    const clientId = String(details.params.client_id);
    const application = await s.apps.getByClientId(clientId);
    let result: InteractionResults;
    if (!application || !canAccess(user, await s.groups.groupIdsForUser(user.id), application)) {
      await s.audit.record({
        actor: { type: 'user', id: user.id },
        action: 'oidc.access_denied',
        target: clientId,
        ip: req.ip,
      });
      result = { error: 'access_denied', error_description: 'You do not have access to this application' };
    } else {
      const existing = details.grantId ? await provider.Grant.find(details.grantId) : undefined;
      const grant =
        existing && existing.accountId === user.id ? existing : new provider.Grant({ accountId: user.id, clientId });
      grant.addOIDCScope(typeof details.params.scope === 'string' ? details.params.scope : 'openid');
      const missing = details.prompt.details as PromptDetails;
      if (missing.missingOIDCClaims?.length) grant.addOIDCClaims(missing.missingOIDCClaims);
      for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes ?? {})) {
        grant.addResourceScope(indicator, scopes.join(' '));
      }
      result = { login: { accountId: user.id }, consent: { grantId: await grant.save() } };
    }

    reply.hijack();
    await provider.interactionFinished(req.raw, reply.raw, result, { mergeWithLastSubmission: false });
  });
}
```

- [ ] **Step 7: Mount in the app** — `src/http/app.ts`

Add imports:
```ts
import middie from '@fastify/middie';
import { errors as oidcErrors } from 'oidc-provider';
import { registerInteractionRoutes } from './interaction-routes.js';
```
At the top of `describeError` add:
```ts
  if (err instanceof oidcErrors.SessionNotFound) {
    return {
      status: 400,
      title: 'Sign-in expired',
      detail: 'Your sign-in request expired. Go back to the application and try again.',
    };
  }
```
After `await app.register(formbody);` add:
```ts
  await app.register(middie);
  // oidc-provider is a Koa app; middie hands it the raw request before Fastify parses the body.
  app.use('/oidc', (req, res) => s.oidc.handle(req, res));
```
After `registerLoginRoutes(app, s);` add `registerInteractionRoutes(app, s);`.

- [ ] **Step 8: Key rotation endpoint** — `src/api/keys.ts`

```ts
import type { FastifyInstance } from 'fastify';
import type { Services } from '../services.js';
import { recordAudit } from './common.js';

export function registerKeyRoutes(api: FastifyInstance, s: Services): void {
  api.post('/keys/rotate', async (req, reply) => {
    await s.keys.rotate();
    await s.oidc.load();
    await recordAudit(s, req, 'keys.rotate');
    return reply.code(204).send();
  });
}
```

In `src/api/plugin.ts` add `import { registerKeyRoutes } from './keys.js';` and call `registerKeyRoutes(api, s);` after `registerAuditRoutes(api, s);`.

- [ ] **Step 9: Run the full suite**

Run: `npm test && npm run typecheck`
Expected: all tests PASS (earlier HTTP/API tests now also run with a loaded provider).

If `ctx.oidc.session` is typed as non-optional in `@types/oidc-provider`, the `?.` in the login check is still valid; if TypeScript reports the `jwks` cast as incompatible, cast via `as unknown as NonNullable<Configuration['jwks']>['keys']`.

- [ ] **Step 10: Commit**

```bash
git add src/oidc src/services.ts src/http src/api tests/helpers tests/oidc/flow.test.ts
git commit -m "feat: add OIDC provider with Auth.i session-backed login and access policy"
```

---
### Task 13: Forward-auth endpoint

**Files:**
- Create: `src/forward-auth/routes.ts`
- Modify: `src/http/app.ts` (register route)
- Test: `tests/forward-auth.test.ts`

**Interfaces:**
- Consumes: `Services`, `currentUser`, `canAccess`.
- Produces: `export function registerForwardAuthRoutes(app: FastifyInstance, s: Services): void;` serving `GET /outpost/auth[?mode=nginx]`.
  - Reads `X-Forwarded-Proto` (default `https`), `X-Forwarded-Host` (required; port ignored for matching), `X-Forwarded-Uri` (default `/`).
  - `400` missing host · `403` unknown host or forward-auth disabled · no session → `302` to `<issuer>/login?rd=<original URL>` (or `401` with `mode=nginx`) · signed in but not allowed → `403` · allowed → `200` with identity headers.

- [ ] **Step 1: Write the failing test** — `tests/forward-auth.test.ts`

```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Group } from '../src/identity/groups.js';
import type { User } from '../src/identity/users.js';
import { createTestContext, type TestContext } from './helpers/app.js';

let ctx: TestContext;
let zoe: User;
let rnd: Group;
let sessionToken: string;

beforeEach(async () => {
  ctx = await createTestContext({ issuerUrl: 'https://auth.example.test', cookieDomain: '.example.test' });
  const s = ctx.services;
  zoe = await s.users.create({ username: 'zoe', email: 'zoe@example.test', displayName: 'Zoë Ångström' });
  rnd = await s.groups.create({ name: 'R&D, Ops' });
  await s.groups.addMember(rnd.id, zoe.id);
  await s.apps.create({
    slug: 'wiki',
    name: 'Wiki',
    forwardAuthEnabled: true,
    externalHost: 'wiki.example.test',
    allowedGroupIds: [rnd.id],
  });
  ({ token: sessionToken } = await s.sessions.create(zoe.id));
});
afterEach(() => ctx.close());

function check(headers: Record<string, string>, opts: { session?: string; query?: string } = {}) {
  return ctx.app.inject({
    method: 'GET',
    url: `/outpost/auth${opts.query ?? ''}`,
    headers: { 'x-forwarded-proto': 'https', 'x-forwarded-uri': '/page?x=1', ...headers },
    cookies: opts.session ? { authi_session: opts.session } : {},
  });
}

describe('GET /outpost/auth', () => {
  it('requires X-Forwarded-Host', async () => {
    expect((await check({})).statusCode).toBe(400);
  });

  it('rejects unknown hosts', async () => {
    expect((await check({ 'x-forwarded-host': 'other.example.test' }, { session: sessionToken })).statusCode).toBe(403);
  });

  it('redirects anonymous users to the login page with the original URL', async () => {
    const res = await check({ 'x-forwarded-host': 'wiki.example.test' });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.origin + location.pathname).toBe('https://auth.example.test/login');
    expect(location.searchParams.get('rd')).toBe('https://wiki.example.test/page?x=1');
  });

  it('answers 401 for anonymous users in nginx mode', async () => {
    expect((await check({ 'x-forwarded-host': 'wiki.example.test' }, { query: '?mode=nginx' })).statusCode).toBe(401);
  });

  it('returns identity headers, encoding non-ASCII names and commas in group names', async () => {
    const res = await check({ 'x-forwarded-host': 'Wiki.Example.test:443' }, { session: sessionToken });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-authi-user']).toBe('zoe');
    expect(res.headers['x-authi-email']).toBe('zoe@example.test');
    expect(res.headers['x-authi-uid']).toBe(zoe.id);
    expect(decodeURIComponent(res.headers['x-authi-name'] as string)).toBe('Zoë Ångström');
    const groups = (res.headers['x-authi-groups'] as string).split(',').map(decodeURIComponent);
    expect(groups).toEqual(['R&D, Ops']);
  });

  it('forbids signed-in users outside the allowed groups', async () => {
    await ctx.services.groups.removeMember(rnd.id, zoe.id);
    expect((await check({ 'x-forwarded-host': 'wiki.example.test' }, { session: sessionToken })).statusCode).toBe(403);
  });

  it('treats a deactivated user as signed out', async () => {
    await ctx.services.users.update(zoe.id, { isActive: false });
    expect((await check({ 'x-forwarded-host': 'wiki.example.test' }, { session: sessionToken })).statusCode).toBe(302);
  });

  it('omits the email header when the user has no email', async () => {
    await ctx.services.users.update(zoe.id, { email: null });
    const res = await check({ 'x-forwarded-host': 'wiki.example.test' }, { session: sessionToken });
    expect(res.headers['x-authi-email']).toBe('');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/forward-auth.test.ts`
Expected: FAIL — 404 responses (route not registered).

- [ ] **Step 3: Implement** — `src/forward-auth/routes.ts`

```ts
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { canAccess } from '../apps/policy.js';
import { currentUser } from '../http/context.js';
import type { Services } from '../services.js';

function header(req: FastifyRequest, name: string): string | undefined {
  const value = req.headers[name];
  const first = Array.isArray(value) ? value[0] : value;
  return first?.split(',')[0]?.trim() || undefined;
}

export function registerForwardAuthRoutes(app: FastifyInstance, s: Services): void {
  app.get<{ Querystring: { mode?: string } }>('/outpost/auth', async (req, reply) => {
    const host = header(req, 'x-forwarded-host');
    if (!host) return reply.code(400).send('Missing X-Forwarded-Host');
    const proto = header(req, 'x-forwarded-proto') === 'http' ? 'http' : 'https';
    const uri = header(req, 'x-forwarded-uri') ?? '/';
    const original = `${proto}://${host}${uri.startsWith('/') ? uri : `/${uri}`}`;

    const application = await s.apps.getByExternalHost(host.replace(/:\d+$/, ''));
    if (!application || !application.forwardAuthEnabled) return reply.code(403).send('Unknown application');

    const user = await currentUser(req, s);
    if (!user) {
      if (req.query.mode === 'nginx') return reply.code(401).send('Authentication required');
      return reply.redirect(`${s.config.issuerUrl}/login?rd=${encodeURIComponent(original)}`, 302);
    }

    if (!canAccess(user, await s.groups.groupIdsForUser(user.id), application)) {
      await s.audit.record({
        actor: { type: 'user', id: user.id },
        action: 'forward_auth.access_denied',
        target: application.slug,
        ip: req.ip,
      });
      return reply.code(403).send('You do not have access to this application');
    }

    const groups = await s.users.groupNames(user.id);
    return reply
      .header('X-Authi-User', user.username)
      .header('X-Authi-Email', user.email ?? '')
      .header('X-Authi-Name', encodeURIComponent(user.displayName))
      .header('X-Authi-Groups', groups.map(encodeURIComponent).join(','))
      .header('X-Authi-Uid', user.id)
      .code(200)
      .send();
  });
}
```

In `src/http/app.ts` add `import { registerForwardAuthRoutes } from '../forward-auth/routes.js';` and call `registerForwardAuthRoutes(app, s);` after `registerInteractionRoutes(app, s);`.

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/forward-auth.test.ts && npm run typecheck`
Expected: 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/forward-auth src/http/app.ts tests/forward-auth.test.ts
git commit -m "feat: add forward-auth endpoint for reverse proxies"
```

---
### Task 14: Bootstrap, maintenance, CLI, server entry and Docker

**Files:**
- Create: `src/bootstrap.ts`, `src/maintenance.ts`, `src/cli/commands.ts`, `src/cli.ts`, `src/server.ts`
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `.env.example`, `README.md`
- Test: `tests/ops.test.ts`

**Interfaces:**
- Consumes: everything above.
- Produces:
  ```ts
  // bootstrap.ts
  export function ensureBootstrapAdmin(s: Pick<Services, 'users' | 'audit' | 'config'>): Promise<'created' | 'skipped'>;
  // maintenance.ts
  export function runMaintenanceOnce(s: Pick<Services, 'sessions' | 'limiter' | 'db'>): Promise<void>;
  export function startMaintenance(s: Pick<Services, 'sessions' | 'limiter' | 'db'>, onError: (err: unknown) => void, intervalMs?: number): () => void;
  // cli/commands.ts
  export const USAGE: string;
  export function runCommand(s: Services, argv: string[]): Promise<string>;
  ```
- CLI: `node dist/cli.js create-api-token <name>` · `create-admin <username> [email]` · `reset-password <username-or-email>` (inside the container: `docker compose exec authi node dist/cli.js …`).

- [ ] **Step 1: Write the failing test** — `tests/ops.test.ts`

```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ensureBootstrapAdmin } from '../src/bootstrap.js';
import { runCommand, USAGE } from '../src/cli/commands.js';
import { runMaintenanceOnce } from '../src/maintenance.js';
import { PostgresAdapter } from '../src/oidc/adapter.js';
import { createTestContext, TEST_PASSWORD, type TestContext } from './helpers/app.js';

let ctx: TestContext;
beforeEach(async () => {
  ctx = await createTestContext({
    bootstrapAdmin: { username: 'admin', password: TEST_PASSWORD, email: 'admin@example.test' },
  });
});
afterEach(() => ctx.close());

describe('ensureBootstrapAdmin', () => {
  it('creates the admin once and never resets the password', async () => {
    expect(await ensureBootstrapAdmin(ctx.services)).toBe('created');
    const admin = (await ctx.services.users.findByLogin('admin'))!.user;
    expect(admin).toMatchObject({ isAdmin: true, email: 'admin@example.test' });
    await ctx.services.users.setPassword(admin.id, 'changed-password-123');
    expect(await ensureBootstrapAdmin(ctx.services)).toBe('skipped');
    expect((await ctx.services.localAuth.authenticate('admin', 'changed-password-123', '127.0.0.1')).ok).toBe(true);
    expect(await ctx.services.users.count()).toBe(1);
  });

  it('skips without bootstrap configuration', async () => {
    const services = { ...ctx.services, config: { ...ctx.services.config, bootstrapAdmin: undefined } };
    expect(await ensureBootstrapAdmin(services)).toBe('skipped');
  });
});

describe('runMaintenanceOnce', () => {
  it('purges expired sessions and OIDC payloads', async () => {
    const user = await ctx.services.users.create({ username: 'alice' });
    const { session } = await ctx.services.sessions.create(user.id);
    await ctx.services.db.updateTable('sessions').set({ expires_at: new Date(Date.now() - 1000) }).where('id', '=', session.id).execute();
    await new PostgresAdapter('AccessToken', ctx.services.db, async () => undefined).upsert('t', {}, -1);
    await runMaintenanceOnce(ctx.services);
    expect(await ctx.services.db.selectFrom('sessions').selectAll().execute()).toHaveLength(0);
    expect(await ctx.services.db.selectFrom('oidc_payloads').selectAll().execute()).toHaveLength(0);
  });
});

describe('CLI commands', () => {
  it('creates an API token that works', async () => {
    const out = await runCommand(ctx.services, ['create-api-token', 'laptop']);
    const token = out.match(/authi_[A-Za-z0-9_-]+/)![0];
    expect(await ctx.services.apiTokens.verify(token)).not.toBeNull();
  });

  it('creates an admin with a generated password', async () => {
    const out = await runCommand(ctx.services, ['create-admin', 'root', 'root@example.test']);
    const password = out.match(/Password: (\S+)/)![1]!;
    expect(password.length).toBeGreaterThanOrEqual(12);
    const result = await ctx.services.localAuth.authenticate('root', password, '127.0.0.1');
    expect(result.ok && result.user.isAdmin).toBe(true);
  });

  it('resets a password and ends sessions', async () => {
    const user = await ctx.services.users.create({ username: 'alice', password: TEST_PASSWORD });
    const { token } = await ctx.services.sessions.create(user.id);
    const out = await runCommand(ctx.services, ['reset-password', 'ALICE']);
    const password = out.match(/Password: (\S+)/)![1]!;
    expect((await ctx.services.localAuth.authenticate('alice', password, '127.0.0.1')).ok).toBe(true);
    expect(await ctx.services.sessions.validate(token)).toBeNull();
  });

  it('reports usage and errors', async () => {
    expect(await runCommand(ctx.services, [])).toBe(USAGE);
    await expect(runCommand(ctx.services, ['create-api-token'])).rejects.toThrow(/Usage/);
    await expect(runCommand(ctx.services, ['reset-password', 'nobody'])).rejects.toThrow(/not found/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ops.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement**

`src/bootstrap.ts`:
```ts
import type { Services } from './services.js';

export async function ensureBootstrapAdmin(s: Pick<Services, 'users' | 'audit' | 'config'>): Promise<'created' | 'skipped'> {
  const bootstrap = s.config.bootstrapAdmin;
  if (!bootstrap || (await s.users.count()) > 0) return 'skipped';
  const user = await s.users.create({
    username: bootstrap.username,
    email: bootstrap.email ?? null,
    password: bootstrap.password,
    isAdmin: true,
  });
  await s.audit.record({ actor: { type: 'system' }, action: 'user.bootstrap', target: user.id });
  return 'created';
}
```

`src/maintenance.ts`:
```ts
import { purgeExpiredOidcPayloads } from './oidc/adapter.js';
import type { Services } from './services.js';

type MaintenanceDeps = Pick<Services, 'sessions' | 'limiter' | 'db'>;

export async function runMaintenanceOnce(s: MaintenanceDeps): Promise<void> {
  await s.sessions.purgeExpired();
  await s.limiter.purge();
  await purgeExpiredOidcPayloads(s.db);
}

export function startMaintenance(
  s: MaintenanceDeps,
  onError: (err: unknown) => void,
  intervalMs = 10 * 60 * 1000,
): () => void {
  const timer = setInterval(() => {
    runMaintenanceOnce(s).catch(onError);
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
```

`src/cli/commands.ts`:
```ts
import { randomToken } from '../crypto/secrets.js';
import type { Services } from '../services.js';

export const USAGE = `Usage: authi <command>

Commands:
  create-api-token <name>            Create an admin API token (shown once)
  create-admin <username> [email]    Create an admin user with a generated password
  reset-password <username-or-email> Generate a new password and end the user's sessions`;

export async function runCommand(s: Services, argv: string[]): Promise<string> {
  const [command, ...args] = argv;
  switch (command) {
    case 'create-api-token': {
      const name = args[0];
      if (!name) throw new Error('Usage: create-api-token <name>');
      const { token, apiToken } = await s.apiTokens.create({ name });
      await s.audit.record({ actor: { type: 'system' }, action: 'api_token.create', target: apiToken.id, details: { name, via: 'cli' } });
      return `API token "${name}" created. It is shown only once:\n${token}`;
    }
    case 'create-admin': {
      const [username, email] = args;
      if (!username) throw new Error('Usage: create-admin <username> [email]');
      const password = randomToken(18);
      const user = await s.users.create({ username, email: email ?? null, password, isAdmin: true });
      await s.audit.record({ actor: { type: 'system' }, action: 'user.create', target: user.id, details: { via: 'cli' } });
      return `Admin "${username}" created.\nPassword: ${password}`;
    }
    case 'reset-password': {
      const identifier = args[0];
      if (!identifier) throw new Error('Usage: reset-password <username-or-email>');
      const found = await s.users.findByLogin(identifier);
      if (!found) throw new Error(`User "${identifier}" not found`);
      const password = randomToken(18);
      await s.users.setPassword(found.user.id, password);
      await s.sessions.destroyAllForUser(found.user.id);
      await s.audit.record({ actor: { type: 'system' }, action: 'user.password_set', target: found.user.id, details: { via: 'cli' } });
      return `Password for "${found.user.username}" reset.\nPassword: ${password}`;
    }
    default:
      return USAGE;
  }
}
```

`src/cli.ts`:
```ts
import { runCommand } from './cli/commands.js';
import { loadConfig } from './config.js';
import { createDb } from './db/db.js';
import { runMigrations } from './db/migrate.js';
import { createServices } from './services.js';

const config = loadConfig();
const db = createDb(config.databaseUrl);
try {
  await runMigrations(db);
  console.log(await runCommand(createServices(config, db), process.argv.slice(2)));
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
} finally {
  await db.destroy();
}
```

`src/server.ts`:
```ts
import type { FastifyBaseLogger } from 'fastify';
import { ensureBootstrapAdmin } from './bootstrap.js';
import { loadConfig } from './config.js';
import { createDb } from './db/db.js';
import { runMigrations } from './db/migrate.js';
import { buildApp } from './http/app.js';
import { startMaintenance } from './maintenance.js';
import { createServices, startServices } from './services.js';

const config = loadConfig();
const db = createDb(config.databaseUrl);
await runMigrations(db);

let log: FastifyBaseLogger | undefined;
const services = createServices(config, db, {
  onEventError: (err, event) => log?.error({ err, event }, 'event handler failed'),
});
await startServices(services);

const app = await buildApp(services, { logger: { level: config.logLevel } });
log = app.log;

if ((await ensureBootstrapAdmin(services)) === 'created') {
  app.log.info({ username: config.bootstrapAdmin?.username }, 'bootstrap admin created');
}
const stopMaintenance = startMaintenance(services, (err) => app.log.error({ err }, 'maintenance failed'));

await app.listen({ port: config.port, host: '0.0.0.0' });

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    app.log.info({ signal }, 'shutting down');
    stopMaintenance();
    await app.close();
    await db.destroy();
    process.exit(0);
  });
}
```

- [ ] **Step 4: Run tests**

Run: `npm test && npm run typecheck && npm run build`
Expected: all tests PASS; `dist/server.js` and `dist/cli.js` exist.

- [ ] **Step 5: Docker files**

`Dockerfile`:
```dockerfile
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY migrations ./migrations
COPY views ./views
USER node
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:9000/healthz || exit 1
CMD ["node", "dist/server.js"]
```

`.dockerignore`:
```
node_modules
dist
tests
docs
.git
.env
```

`docker-compose.yml`:
```yaml
services:
  authi:
    build: .
    image: authi:latest
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgres://authi:${POSTGRES_PASSWORD}@postgres:5432/authi
    ports:
      - "9000:9000"
    depends_on:
      postgres:
        condition: service_healthy
    # Behind Traefik, replace `ports` with labels like:
    # labels:
    #   - traefik.enable=true
    #   - traefik.http.routers.authi.rule=Host(`auth.example.com`)
    #   - traefik.http.services.authi.loadbalancer.server.port=9000
    #   - traefik.http.middlewares.authi.forwardauth.address=http://authi:9000/outpost/auth
    #   - traefik.http.middlewares.authi.forwardauth.trustForwardHeader=true
    #   - traefik.http.middlewares.authi.forwardauth.authResponseHeaders=X-Authi-User,X-Authi-Email,X-Authi-Name,X-Authi-Groups,X-Authi-Uid

  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: authi
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: authi
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authi -d authi"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  pgdata:
```

`.env.example`:
```
# Public URL of Auth.i (no trailing slash)
AUTHI_ISSUER_URL=https://auth.example.com
# Parent domain shared by Auth.i and forward-auth apps (leave empty to scope cookies to AUTHI_ISSUER_URL's host)
AUTHI_COOKIE_DOMAIN=.example.com
# openssl rand -base64 32
AUTHI_SECRET_KEY=
# openssl rand -hex 24
POSTGRES_PASSWORD=
# First admin, created only when the database has no users
AUTHI_BOOTSTRAP_ADMIN_USER=admin
AUTHI_BOOTSTRAP_ADMIN_PASSWORD=
AUTHI_BOOTSTRAP_ADMIN_EMAIL=
LOG_LEVEL=info
```

- [ ] **Step 6: README** — `README.md`

````markdown
# Auth.i

Self-hosted single sign-on for your own apps. Auth.i is an OpenID Connect provider and a forward-auth
endpoint for Traefik, Caddy and nginx, backed by Postgres and managed through a REST API.

Status: plan 1 of 4 (local users). Next: AD/Entra sign-in sources, SCIM provisioning, admin UI.

## Run it

```bash
cp .env.example .env    # fill in AUTHI_SECRET_KEY, POSTGRES_PASSWORD, bootstrap admin password
docker compose up -d --build
docker compose exec authi node dist/cli.js create-api-token laptop
```

Put Auth.i behind your reverse proxy with TLS at `AUTHI_ISSUER_URL`.

## Connect an app with OIDC

```bash
curl -X POST https://auth.example.com/api/v1/applications \
  -H "Authorization: Bearer $AUTHI_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"grafana","name":"Grafana","oidcEnabled":true,
       "redirectUris":["https://grafana.example.com/login/generic_oauth"],
       "launchUrl":"https://grafana.example.com"}'
```

The response holds `clientSecret` (shown once). Configure the app with:

| Setting | Value |
|---|---|
| Issuer / discovery | `https://auth.example.com/oidc` (`/.well-known/openid-configuration`) |
| Client ID | the slug |
| Scopes | `openid profile email groups` (add `offline_access` if the app asks for it) |
| Groups claim | `groups` |

Restrict access with `"allowedGroupIds": ["<group id>"]`.

## Protect an app without OIDC (forward-auth)

Create the app with `"forwardAuthEnabled": true, "externalHost": "wiki.example.com"`, then:

Traefik: see the commented labels in `docker-compose.yml` and add the `authi` middleware to the app's router.

Caddy:
```
wiki.example.com {
  forward_auth authi:9000 {
    uri /outpost/auth
    copy_headers X-Authi-User X-Authi-Email X-Authi-Name X-Authi-Groups X-Authi-Uid
  }
  reverse_proxy wiki:8080
}
```

nginx:
```
location = /authi { internal; proxy_pass http://authi:9000/outpost/auth?mode=nginx;
  proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Uri $request_uri;
  proxy_set_header X-Forwarded-Proto $scheme; proxy_pass_request_body off; proxy_set_header Content-Length ""; }
location / { auth_request /authi; error_page 401 = @login;
  auth_request_set $authi_user $upstream_http_x_authi_user; proxy_set_header X-Authi-User $authi_user;
  proxy_pass http://wiki:8080; }
location @login { return 302 https://auth.example.com/login?rd=$scheme://$host$request_uri; }
```

`X-Authi-Name` and each entry of the comma-separated `X-Authi-Groups` are URL-encoded; decode them in the app.
The app host must sit under `AUTHI_COOKIE_DOMAIN` so the browser sends the Auth.i session cookie.

## API

All endpoints live under `/api/v1` and need `Authorization: Bearer <token>`: `users`, `groups`,
`groups/{id}/members/{userId}`, `applications`, `applications/{id}/secret`, `api-tokens`, `audit-log`,
`keys/rotate`. Errors use `application/problem+json`.

## Development

```bash
npm install
npm run db:test:up   # Postgres for tests on port 55432
npm test
```
````

- [ ] **Step 7: Docker smoke test**

```bash
cat > .env <<EOF
AUTHI_ISSUER_URL=http://localhost:9000
AUTHI_SECRET_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
AUTHI_BOOTSTRAP_ADMIN_USER=admin
AUTHI_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 12)
EOF
docker compose up -d --build --wait
curl -fsS http://localhost:9000/healthz
curl -fsS http://localhost:9000/oidc/.well-known/openid-configuration | head -c 200; echo
docker compose exec authi node dist/cli.js create-api-token smoke
docker compose restart authi && docker compose up -d --wait && curl -fsS http://localhost:9000/healthz
docker compose logs authi | grep -c "bootstrap admin created"
docker compose down -v
rm .env
```
Expected: `{"status":"ok"}` twice, discovery JSON with `"issuer":"http://localhost:9000/oidc"`, a printed `authi_…` token, and the bootstrap log line counted exactly `1` (restart did not recreate the admin).

- [ ] **Step 8: Commit**

```bash
git add src/bootstrap.ts src/maintenance.ts src/cli src/cli.ts src/server.ts Dockerfile .dockerignore docker-compose.yml .env.example README.md tests/ops.test.ts
git commit -m "feat: add bootstrap admin, maintenance, CLI and Docker deployment"
```
