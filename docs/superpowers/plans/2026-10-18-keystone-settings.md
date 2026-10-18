# Keystone Settings and First-Run Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keystone deploys with no `.env`. A one-time-code setup screen creates the first admin and stores the public URL, and an admin Settings page manages the public URL, cookie domain, trusted proxies and log level. Environment variables are optional overrides.

**Architecture:**
- Settings live in a new `settings` table behind a `SettingsService`. It resolves each value as env override, then database value, then default.
- Every consumer of `issuerUrl`, `cookieDomain` and `secureCookies` reads `settings.current()` at use time, so changes apply live. The OIDC provider is rebuilt through the existing `OidcProviderHolder.load()`.
- A `SetupService` plus an `onRequest` gate handles first run.
- Admin pages are server-rendered Eta views behind a `requireAdmin` guard.

**Tech Stack:** Node.js 24, TypeScript 5.9 ESM, Fastify 5, Eta 4, Kysely + pg, zod 4, oidc-provider 9, vitest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-18-keystone-settings-design.md`

## Global Constraints

- ESM only; relative imports end in `.js`. No new npm dependencies.
- Settings keys: `issuerUrl` (env `KEYSTONE_ISSUER_URL`, default `http://localhost:9000`), `cookieDomain` (env `KEYSTONE_COOKIE_DOMAIN`, default unset), `trustProxy` (env `KEYSTONE_TRUST_PROXY`, default `loopback,linklocal,uniquelocal`), `logLevel` (env `LOG_LEVEL`, default `info`).
- Precedence: env var present and non-empty → value from env, locked in the UI. Otherwise the database value. Otherwise the default.
- `secureCookies` = effective `issuerUrl` starts with `https://`.
- Setup advisory lock constant `7_424_245`. The constants `7_424_242`–`7_424_244` are taken.
- Setup code: 16 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, shown as `XXXX-XXXX-XXXX-XXXX`. Only its SHA-256 hash is kept, in memory. Comparison is constant-time. Limit: 5 attempts per IP per 15 minutes.
- Setup is complete when at least one user exists.
- Username `^[a-zA-Z0-9._@-]{2,64}$`; password ≥ 12 characters (reuse `usernameSchema` / `passwordSchema` from `src/api/common.ts`).
- Every admin POST requires CSRF (`verifyCsrfToken`) and an `is_admin` session. Non-admin → 403. Signed out → redirect to `/login?rd=<path>`.
- CSP has no `script-src`, so inline scripts are blocked. The admin pages use no JavaScript, and the restart page refreshes with `<meta http-equiv="refresh">`.
- Never modify the existing default Compose project's volumes. The smoke test uses `docker compose -p keystone-smoke` and `down -v` only on that project.
- Commit message trailer: your session's `Co-Authored-By` line.

## Review Focus

1. **The public URL entered as `https://auth.example.com/` or with a path, query or uppercase letters** must be stored normalised as `https://auth.example.com` or rejected, never break OIDC. Task 1 tests this.
2. **Saving settings while an env var locks a field, via a crafted POST that includes the locked key,** must be rejected with no partial save. Tasks 1 and 4 test this.
3. **Setup code typed lowercase, with spaces, or without dashes** must still be accepted, and a wrong code must not consume setup. Task 3 tests this.
4. **The setup gate** must not block `/healthz`, or the container healthcheck fails and Docker restarts it forever. Task 3 tests this.
5. **A cookie domain that does not cover the public URL host** (for example `evil.com`) must be rejected. Task 1 tests this.

## File Structure

```
migrations/002_settings.sql        settings table
src/settings/keys.ts               SETTING_KEYS, SettingKey, env var names
src/settings/settings.ts           SettingsService, validation, SettingsValidationError
src/setup/setup.ts                 SetupService (code, completion under lock)
src/http/setup-routes.ts           GET/POST /setup + setup gate hook
src/http/admin-guard.ts            requireAdmin
src/http/admin-routes.ts           /admin, /admin/settings, /admin/restart
views/setup.eta                    setup card
views/admin/layout.eta             admin shell (sidebar)
views/admin/settings.eta           settings form
views/admin/restarting.eta         restart page (meta refresh)
modified: src/config.ts (settingsFromEnv), src/db/schema.ts, src/events/bus.ts, src/services.ts,
          src/http/context.ts, src/http/csrf.ts, src/http/login-routes.ts, src/http/app.ts,
          src/forward-auth/routes.ts, src/oidc/provider.ts, src/server.ts, views/layout.eta,
          views/home.eta, tests/helpers/app.ts, docker-compose.yml, README.md, .env.example
tests/settings/settings.test.ts, tests/settings/live.test.ts, tests/http/setup.test.ts, tests/http/admin.test.ts
```

---

### Task 1: Settings store and SettingsService

**Files:**
- Create: `migrations/002_settings.sql`, `src/settings/keys.ts`, `src/settings/settings.ts`
- Modify: `src/config.ts`, `src/db/schema.ts`, `src/events/bus.ts`, `tests/helpers/app.ts`
- Test: `tests/settings/settings.test.ts`

**Interfaces:**
- Consumes: `Db` (`src/db/db.ts`), `AuditLog` + `Actor` (`src/audit/audit.ts`), `EventBus` (`src/events/bus.ts`), `Config` (`src/config.ts`).
- Produces:
  ```ts
  // src/settings/keys.ts
  export const SETTING_KEYS = ['issuerUrl', 'cookieDomain', 'trustProxy', 'logLevel'] as const;
  export type SettingKey = (typeof SETTING_KEYS)[number];
  export const SETTING_ENV: Record<SettingKey, string>;   // issuerUrl→'KEYSTONE_ISSUER_URL', cookieDomain→'KEYSTONE_COOKIE_DOMAIN', trustProxy→'KEYSTONE_TRUST_PROXY', logLevel→'LOG_LEVEL'
  export const LOG_LEVELS = ['fatal','error','warn','info','debug','trace','silent'] as const;
  // src/config.ts — Config gains:
  settingsFromEnv: ReadonlySet<SettingKey>;
  // src/settings/settings.ts
  export interface EffectiveSettings { issuerUrl: string; cookieDomain: string | undefined; secureCookies: boolean; trustProxy: string; logLevel: string }
  export interface SettingInfo { key: SettingKey; value: string; locked: boolean; envVar: string; source: 'env' | 'database' | 'default' }
  export class SettingsValidationError extends Error { fieldErrors: Partial<Record<SettingKey, string>> }
  export class SettingsService {
    constructor(db: Db, config: Config, events: EventBus, audit: AuditLog);
    load(): Promise<void>;
    current(): EffectiveSettings;
    describe(): SettingInfo[];
    isLocked(key: SettingKey): boolean;
    validate(patch: Partial<Record<SettingKey, string>>): Partial<Record<SettingKey, string>>; // returns normalised values or throws SettingsValidationError
    update(patch: Partial<Record<SettingKey, string>>, actor: Actor, ip?: string): Promise<SettingKey[]>; // returns changed keys
  }
  // src/events/bus.ts — DomainEvent gains: { type: 'settings.changed'; keys: string[] }
  ```

- [ ] **Step 1: Migration and schema**

`migrations/002_settings.sql`:
```sql
CREATE TABLE settings (
  key         text PRIMARY KEY,
  value       jsonb NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL
);
```

In `src/db/schema.ts`, add a `SettingsTable`. Follow the file's existing conventions for `ColumnType`/`Generated` and for jsonb columns: look at how `audit_log.details` is typed and copy that shape for `value`.
```ts
export interface SettingsTable {
  key: string;
  value: ColumnType<unknown, string, string>;
  updated_at: ColumnType<Date, Date | undefined, Date>;
  updated_by: string | null;
}
```
Register it in the database interface as `settings: SettingsTable;`.

- [ ] **Step 2: Keys module**

`src/settings/keys.ts`:
```ts
export const SETTING_KEYS = ['issuerUrl', 'cookieDomain', 'trustProxy', 'logLevel'] as const;
export type SettingKey = (typeof SETTING_KEYS)[number];

export const SETTING_ENV: Record<SettingKey, string> = {
  issuerUrl: 'KEYSTONE_ISSUER_URL',
  cookieDomain: 'KEYSTONE_COOKIE_DOMAIN',
  trustProxy: 'KEYSTONE_TRUST_PROXY',
  logLevel: 'LOG_LEVEL',
};

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
```

- [ ] **Step 3: Config records which settings came from env**

In `src/config.ts`:
1. Import `SETTING_ENV, SETTING_KEYS, type SettingKey` from `./settings/keys.js`.
2. Add `settingsFromEnv: ReadonlySet<SettingKey>;` to `Config`.
3. In `loadConfig`, compute it from the already-filtered `present` object and return it:
```ts
settingsFromEnv: new Set(SETTING_KEYS.filter((k) => present[SETTING_ENV[k]] !== undefined)),
```

In `tests/helpers/app.ts` `testConfig`, add `settingsFromEnv: new Set(['issuerUrl', 'cookieDomain', 'trustProxy', 'logLevel'] as const),` before `...overrides`. Then every existing test keeps using its config values exactly as before. New tests pass `settingsFromEnv: new Set()`.

In `tests/config.test.ts`, add one test:
```ts
it('records which settings come from the environment', () => {
  const c = loadConfig({ KEYSTONE_ISSUER_URL: 'https://a.example.test', LOG_LEVEL: 'debug', KEYSTONE_COOKIE_DOMAIN: '' }, { dataDir: tmp });
  expect([...c.settingsFromEnv].sort()).toEqual(['issuerUrl', 'logLevel']);
});
```
Use whatever temp-dir fixture the file already uses for `dataDir` (name it to match). The file also needs a database password fixture, or a `DATABASE_URL` entry, the same way the existing tests do it.

- [ ] **Step 4: Event type**

In `src/events/bus.ts`, add `| { type: 'settings.changed'; keys: string[] }` to `DomainEvent`.

- [ ] **Step 5: Write the failing SettingsService tests**

`tests/settings/settings.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit/audit.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { SettingsService, SettingsValidationError } from '../../src/settings/settings.js';
import type { SettingKey } from '../../src/settings/keys.js';
import { testConfig } from '../helpers/app.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let events: DomainEvent[];

function make(locked: SettingKey[] = [], overrides = {}) {
  const bus = new EventBus();
  bus.subscribe((e) => void events.push(e));
  const config = testConfig({ settingsFromEnv: new Set(locked), issuerUrl: 'http://localhost:9000', ...overrides });
  return new SettingsService(t.db, config, bus, new AuditLog(t.db));
}
const actor = { type: 'system' } as const;

beforeEach(async () => {
  t = await createTestDb();
  events = [];
});
afterEach(() => t.destroy());

describe('SettingsService', () => {
  it('uses defaults when nothing is stored', async () => {
    const s = make();
    await s.load();
    expect(s.current()).toEqual({
      issuerUrl: 'http://localhost:9000',
      cookieDomain: undefined,
      secureCookies: false,
      trustProxy: 'loopback',
      logLevel: 'silent',
    });
    expect(s.describe().find((i) => i.key === 'issuerUrl')).toMatchObject({ source: 'default', locked: false });
  });

  it('stores, normalises and reloads values', async () => {
    const s = make();
    await s.load();
    const changed = await s.update({ issuerUrl: 'HTTPS://Auth.Example.TEST/', cookieDomain: '.Example.test' }, actor);
    expect(changed.sort()).toEqual(['cookieDomain', 'issuerUrl']);
    expect(s.current()).toMatchObject({ issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test', secureCookies: true });
    const again = make();
    await again.load();
    expect(again.current().issuerUrl).toBe('https://auth.example.test');
    expect(again.describe().find((i) => i.key === 'issuerUrl')).toMatchObject({ source: 'database' });
    expect(events).toEqual([{ type: 'settings.changed', keys: expect.arrayContaining(['issuerUrl', 'cookieDomain']) }]);
  });

  it('lets env override the database and rejects updates to locked keys', async () => {
    const s = make(['issuerUrl'], { issuerUrl: 'https://env.example.test' });
    await s.load();
    expect(s.current().issuerUrl).toBe('https://env.example.test');
    await expect(s.update({ issuerUrl: 'https://other.example.test', logLevel: 'debug' }, actor)).rejects.toMatchObject({
      fieldErrors: { issuerUrl: 'Set by KEYSTONE_ISSUER_URL' },
    });
    expect(s.current().logLevel).toBe('silent'); // nothing partially saved
  });

  it.each([
    ['issuerUrl', 'ftp://x.example.test'],
    ['issuerUrl', 'https://x.example.test/path'],
    ['issuerUrl', 'https://x.example.test/?a=1'],
    ['issuerUrl', 'https://user:pw@x.example.test'],
    ['issuerUrl', 'not a url'],
    ['cookieDomain', 'evil.com'],
    ['cookieDomain', 'com'],
    ['trustProxy', '10.0.0.0/99'],
    ['trustProxy', 'loopback,banana'],
    ['logLevel', 'loud'],
  ])('rejects invalid %s %s', async (key, value) => {
    const s = make();
    await s.load();
    await s.update({ issuerUrl: 'https://auth.example.test' }, actor);
    const err = await s.update({ [key]: value }, actor).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SettingsValidationError);
    expect((err as SettingsValidationError).fieldErrors[key as SettingKey]).toBeTruthy();
  });

  it('accepts valid trust proxy forms and clears the cookie domain with an empty value', async () => {
    const s = make();
    await s.load();
    await s.update({ issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test' }, actor);
    await s.update({ trustProxy: 'true' }, actor);
    await s.update({ trustProxy: '127.0.0.1, 10.0.0.0/8, ::1, fd00::/8, loopback' }, actor);
    expect(s.current().trustProxy).toBe('127.0.0.1,10.0.0.0/8,::1,fd00::/8,loopback');
    await s.update({ cookieDomain: '' }, actor);
    expect(s.current().cookieDomain).toBeUndefined();
  });

  it('returns no changed keys and emits nothing when values are unchanged', async () => {
    const s = make();
    await s.load();
    expect(await s.update({ logLevel: 'silent' }, actor)).toEqual([]);
    expect(events).toEqual([]);
  });

  it('records an audit entry with old and new values', async () => {
    const s = make();
    await s.load();
    await s.update({ logLevel: 'debug' }, actor);
    const rows = await t.db.selectFrom('audit_log').selectAll().where('action', '=', 'settings.update').execute();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.details).toEqual({ changes: { logLevel: { from: 'silent', to: 'debug' } } });
  });
});
```
The `audit_log` column names may differ in your schema (`action`, `details`); check `src/audit/audit.ts` and adjust the query to match.

- [ ] **Step 6: Run to see it fail**

Run: `npx vitest run tests/settings/settings.test.ts`
Expected: FAIL, `Cannot find module '../../src/settings/settings.js'`.

- [ ] **Step 7: Implement SettingsService**

`src/settings/settings.ts`:
```ts
import { isIP } from 'node:net';
import type { Actor, AuditLog } from '../audit/audit.js';
import type { Config } from '../config.js';
import type { Db } from '../db/db.js';
import type { EventBus } from '../events/bus.js';
import { LOG_LEVELS, SETTING_ENV, SETTING_KEYS, type SettingKey } from './keys.js';

export interface EffectiveSettings {
  issuerUrl: string;
  cookieDomain: string | undefined;
  secureCookies: boolean;
  trustProxy: string;
  logLevel: string;
}

export interface SettingInfo {
  key: SettingKey;
  value: string;
  locked: boolean;
  envVar: string;
  source: 'env' | 'database' | 'default';
}

export type SettingsPatch = Partial<Record<SettingKey, string>>;

export class SettingsValidationError extends Error {
  constructor(readonly fieldErrors: Partial<Record<SettingKey, string>>) {
    super('Invalid settings');
    this.name = 'SettingsValidationError';
  }
}

const PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normaliseIssuerUrl(raw: string): string {
  const value = raw.trim();
  if (/[\s\u0000-\u001f\u007f]/.test(value)) throw new Error('must not contain spaces or control characters');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('must be a full URL such as https://auth.example.com');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('must start with https:// or http://');
  if (url.username || url.password) throw new Error('must not contain a username or password');
  if (url.pathname !== '/' || url.search || url.hash) throw new Error('must not contain a path, query or fragment');
  return `${url.protocol}//${url.host}`;
}

function hostOf(issuerUrl: string): string {
  return new URL(issuerUrl).hostname.toLowerCase();
}

export function normaliseCookieDomain(raw: string, issuerUrl: string): string | undefined {
  const domain = raw.trim().toLowerCase().replace(/^\.+/, '');
  if (domain === '') return undefined;
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) throw new Error('must be a domain such as example.com');
  const host = hostOf(issuerUrl);
  if (host !== domain && !host.endsWith(`.${domain}`)) {
    throw new Error(`must be ${host} or a parent domain of it`);
  }
  return domain;
}

function validTrustEntry(entry: string): boolean {
  if (PRESETS.has(entry)) return true;
  const [ip, prefix, extra] = entry.split('/');
  if (extra !== undefined || !ip) return false;
  const family = isIP(ip);
  if (family === 0) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (family === 4 ? 32 : 128);
}

export function normaliseTrustProxy(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (value === 'true' || value === 'false') return value;
  const entries = value.split(',').map((e) => e.trim()).filter(Boolean);
  if (entries.length === 0) throw new Error('enter true, false, or a list of addresses');
  const bad = entries.find((e) => !validTrustEntry(e));
  if (bad) throw new Error(`"${bad}" is not an IP address, CIDR range, or loopback/linklocal/uniquelocal`);
  return entries.join(',');
}

export function normaliseLogLevel(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (!(LOG_LEVELS as readonly string[]).includes(value)) throw new Error(`must be one of ${LOG_LEVELS.join(', ')}`);
  return value;
}

export class SettingsService {
  #stored = new Map<SettingKey, string>();

  constructor(
    private readonly db: Db,
    private readonly config: Config,
    private readonly events: EventBus,
    private readonly audit: AuditLog,
  ) {}

  async load(): Promise<void> {
    const rows = await this.db.selectFrom('settings').select(['key', 'value']).execute();
    const next = new Map<SettingKey, string>();
    for (const row of rows) {
      if ((SETTING_KEYS as readonly string[]).includes(row.key) && typeof row.value === 'string') {
        next.set(row.key as SettingKey, row.value);
      }
    }
    this.#stored = next;
  }

  isLocked(key: SettingKey): boolean {
    return this.config.settingsFromEnv.has(key);
  }

  #configValue(key: SettingKey): string | undefined {
    switch (key) {
      case 'issuerUrl':
        return this.config.issuerUrl;
      case 'cookieDomain':
        return this.config.cookieDomain;
      case 'trustProxy':
        return this.config.trustProxy;
      case 'logLevel':
        return this.config.logLevel;
    }
  }

  #value(key: SettingKey): string | undefined {
    if (this.isLocked(key)) return this.#configValue(key);
    return this.#stored.has(key) ? this.#stored.get(key) : this.#configValue(key);
  }

  current(): EffectiveSettings {
    const issuerUrl = this.#value('issuerUrl')!;
    const cookieDomain = this.#value('cookieDomain') || undefined;
    return {
      issuerUrl,
      cookieDomain,
      secureCookies: issuerUrl.startsWith('https://'),
      trustProxy: this.#value('trustProxy')!,
      logLevel: this.#value('logLevel')!,
    };
  }

  describe(): SettingInfo[] {
    return SETTING_KEYS.map((key) => ({
      key,
      value: this.#value(key) ?? '',
      locked: this.isLocked(key),
      envVar: SETTING_ENV[key],
      source: this.isLocked(key) ? 'env' : this.#stored.has(key) ? 'database' : 'default',
    }));
  }

  /** Normalises a patch against the current values; throws SettingsValidationError listing every bad field. */
  validate(patch: SettingsPatch): SettingsPatch {
    const errors: Partial<Record<SettingKey, string>> = {};
    const out: SettingsPatch = {};
    const issuerForDomain = (): string => out.issuerUrl ?? this.current().issuerUrl;
    for (const key of SETTING_KEYS) {
      const raw = patch[key];
      if (raw === undefined) continue;
      if (this.isLocked(key)) {
        if (raw.trim() !== (this.#value(key) ?? '')) errors[key] = `Set by ${SETTING_ENV[key]}`;
        continue;
      }
      try {
        if (key === 'issuerUrl') out.issuerUrl = normaliseIssuerUrl(raw);
        if (key === 'trustProxy') out.trustProxy = normaliseTrustProxy(raw);
        if (key === 'logLevel') out.logLevel = normaliseLogLevel(raw);
      } catch (e) {
        errors[key] = (e as Error).message;
      }
    }
    if (patch.cookieDomain !== undefined && !this.isLocked('cookieDomain') && !errors.issuerUrl) {
      try {
        out.cookieDomain = normaliseCookieDomain(patch.cookieDomain, issuerForDomain()) ?? '';
      } catch (e) {
        errors.cookieDomain = (e as Error).message;
      }
    }
    if (Object.keys(errors).length > 0) throw new SettingsValidationError(errors);
    return out;
  }

  async update(patch: SettingsPatch, actor: Actor, ip?: string): Promise<SettingKey[]> {
    const normalised = this.validate(patch);
    const changes: Partial<Record<SettingKey, { from: string; to: string }>> = {};
    for (const key of SETTING_KEYS) {
      const to = normalised[key];
      if (to === undefined) continue;
      const from = this.#value(key) ?? '';
      if (from !== to) changes[key] = { from, to };
    }
    const changed = Object.keys(changes) as SettingKey[];
    if (changed.length === 0) return [];
    const updatedBy = actor.type === 'user' ? actor.id : null;
    await this.db.transaction().execute(async (trx) => {
      for (const key of changed) {
        await trx
          .insertInto('settings')
          .values({ key, value: JSON.stringify(changes[key]!.to), updated_by: updatedBy })
          .onConflict((oc) =>
            oc.column('key').doUpdateSet({ value: JSON.stringify(changes[key]!.to), updated_at: new Date(), updated_by: updatedBy }),
          )
          .execute();
      }
    });
    await this.load();
    await this.audit.record({ actor, action: 'settings.update', details: { changes }, ...(ip ? { ip } : {}) });
    await this.events.publish({ type: 'settings.changed', keys: changed });
    return changed;
  }
}
```
For a cleared cookie domain, the code stores the empty string `''`. `current()` maps `''` to `undefined` via `|| undefined`, and that overrides a non-empty config default. Check `AuditLog.record`'s input type for the exact `ip`/`details` field names and adjust.

- [ ] **Step 8: Run the tests**

Run: `npx vitest run tests/settings/settings.test.ts tests/config.test.ts`
Expected: PASS. Then run `npm test` and `npm run typecheck`: all pass.

- [ ] **Step 9: Commit**

```bash
git add migrations/002_settings.sql src/settings src/config.ts src/db/schema.ts src/events/bus.ts tests/helpers/app.ts tests/settings/settings.test.ts tests/config.test.ts
git commit -m "feat: add settings store with env overrides"
```

---

### Task 2: Read settings at use time and reload OIDC live

**Files:**
- Modify: `src/services.ts`, `src/http/context.ts`, `src/http/csrf.ts`, `src/http/login-routes.ts`, `src/http/app.ts`, `src/forward-auth/routes.ts`, `src/oidc/provider.ts`, any other file `grep` finds below
- Test: `tests/settings/live.test.ts`

**Interfaces:**
- Consumes: `SettingsService`, `EffectiveSettings`, `SettingKey` (Task 1).
- Produces:
  ```ts
  // src/services.ts
  interface Services { ...existing; settings: SettingsService; log: ServiceLogger }
  export async function applySettingsChange(s: Services, changed: readonly SettingKey[]): Promise<{ oidcReloadFailed: boolean }>;
  // startServices now runs: await s.settings.load(); await s.keys.ensureKeys(); await s.oidc.load();
  // src/http/context.ts
  export function sessionCookieOptions(settings: EffectiveSettings, maxAgeSeconds?: number): CookieSerializeOptions;
  export async function redirectRules(s: Pick<Services, 'settings' | 'apps'>): Promise<RedirectRules>;
  // src/http/csrf.ts
  export function issueCsrfToken(req: FastifyRequest, reply: FastifyReply, settings: EffectiveSettings): string;
  // src/oidc/provider.ts — OidcDeps gains settings: SettingsService; issuer built from d.settings.current().issuerUrl
  ```

- [ ] **Step 1: Write the failing live-settings tests**

`tests/settings/live.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { applySettingsChange } from '../../src/services.js';
import { createTestContext, TEST_PASSWORD, type TestContext } from '../helpers/app.js';

let ctx: TestContext;
const actor = { type: 'system' } as const;
const cookie = (res: { cookies: unknown }, name: string) =>
  (res.cookies as Array<{ name: string; value: string; domain?: string; secure?: boolean }>).find((c) => c.name === name);

beforeEach(async () => {
  ctx = await createTestContext({ settingsFromEnv: new Set(), issuerUrl: 'http://127.0.0.1:9000' });
  await ctx.services.users.create({ username: 'alice', password: TEST_PASSWORD });
});
afterEach(() => ctx.close());

describe('settings apply without restart', () => {
  it('OIDC discovery reports a changed issuer immediately', async () => {
    const before = await ctx.app.inject({ url: '/oidc/.well-known/openid-configuration' });
    expect(before.json().issuer).toBe('http://127.0.0.1:9000/oidc');
    const changed = await ctx.services.settings.update({ issuerUrl: 'https://auth.example.test' }, actor);
    expect(await applySettingsChange(ctx.services, changed)).toEqual({ oidcReloadFailed: false });
    const after = await ctx.app.inject({ url: '/oidc/.well-known/openid-configuration' });
    expect(after.json().issuer).toBe('https://auth.example.test/oidc');
  });

  it('session cookies follow a changed cookie domain and https issuer', async () => {
    await ctx.services.settings.update({ issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test' }, actor);
    const form = await ctx.app.inject({ url: '/login' });
    const csrf = cookie(form, 'keystone_csrf')!;
    expect(csrf.secure).toBe(true);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ csrf: csrf.value, rd: '/', identifier: 'alice', password: TEST_PASSWORD }).toString(),
      cookies: { keystone_csrf: csrf.value },
    });
    expect(res.statusCode).toBe(302);
    expect(cookie(res, 'keystone_session')).toMatchObject({ domain: 'example.test', secure: true });
  });

  it('keeps the old provider when a reload fails', async () => {
    const original = ctx.services.oidc.provider;
    const load = ctx.services.oidc.load.bind(ctx.services.oidc);
    ctx.services.oidc.load = async () => {
      throw new Error('boom');
    };
    expect(await applySettingsChange(ctx.services, ['issuerUrl'])).toEqual({ oidcReloadFailed: true });
    expect(ctx.services.oidc.provider).toBe(original);
    ctx.services.oidc.load = load;
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npx vitest run tests/settings/live.test.ts`
Expected: FAIL, `applySettingsChange` is not exported and `settings` is undefined.

- [ ] **Step 3: Wire SettingsService into services**

In `src/services.ts`:
1. Import `SettingsService` from `./settings/settings.js` and `type SettingKey` from `./settings/keys.js`.
2. Add `settings: SettingsService; log: ServiceLogger;` to `Services`.
3. In `createServices`:
   - build `const log: ServiceLogger = opts.logger ?? { error: (obj, msg) => console.error(msg, obj) };` and use it inside `onEventError`.
   - after `audit`, create `const settings = new SettingsService(db, config, events, audit);`.
   - pass `settings` into `createOidcProvider({ ... , settings })`.
   - return `settings` and `log` as well.
4. `startServices` becomes:
```ts
export async function startServices(s: Services): Promise<void> {
  await s.settings.load();
  await s.keys.ensureKeys();
  await s.oidc.load();
}

/** Applies settings that need more than a fresh read: rebuilds the OIDC provider when its inputs changed. */
export async function applySettingsChange(
  s: Services,
  changed: readonly SettingKey[],
): Promise<{ oidcReloadFailed: boolean }> {
  if (!changed.some((k) => k === 'issuerUrl' || k === 'cookieDomain')) return { oidcReloadFailed: false };
  try {
    await s.oidc.load();
    return { oidcReloadFailed: false };
  } catch (err) {
    s.log.error({ err }, 'OIDC provider reload failed; keeping the previous provider');
    return { oidcReloadFailed: true };
  }
}
```
`OidcProviderHolder.load()` assigns only after the factory resolves, so a failed reload already keeps the old provider. Do not change `holder.ts`.

- [ ] **Step 4: Replace config reads with settings reads**

Run `grep -rn "config\.\(issuerUrl\|cookieDomain\|secureCookies\|trustProxy\|logLevel\)" src | grep -v src/config.ts` and change every hit:
- `src/http/context.ts`:
```ts
export function sessionCookieOptions(settings: EffectiveSettings, maxAgeSeconds?: number): CookieSerializeOptions {
  return {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: settings.secureCookies,
    ...(settings.cookieDomain ? { domain: settings.cookieDomain } : {}),
    ...(maxAgeSeconds !== undefined ? { maxAge: maxAgeSeconds } : {}),
  };
}

export async function redirectRules(s: Pick<Services, 'settings' | 'apps'>): Promise<RedirectRules> {
  const { issuerUrl, cookieDomain } = s.settings.current();
  return { issuerUrl, ...(cookieDomain ? { cookieDomain } : {}), allowedHosts: await s.apps.forwardAuthHosts() };
}
```
  Replace the `Config` import with `import type { EffectiveSettings } from '../settings/settings.js';`.
- `src/http/csrf.ts`: the third parameter becomes `settings: EffectiveSettings` and uses `secure: settings.secureCookies`.
- `src/http/login-routes.ts`: `issueCsrfToken(req, reply, s.settings.current())` and `sessionCookieOptions(s.settings.current(), ...)` in both places.
- `src/http/app.ts`:
  - `trustProxy: parseTrustProxy(s.settings.current().trustProxy)`. This is read once at boot; trusted proxies need a restart.
  - `if (s.settings.current().secureCookies)` for HSTS.
- `src/forward-auth/routes.ts`: `${s.settings.current().issuerUrl}/login?rd=...`.
- `src/oidc/provider.ts`:
  - add `settings: SettingsService` to `OidcDeps` (import the type);
  - `new Provider(`${d.settings.current().issuerUrl}/oidc`, configuration)`;
  - replace any other `d.config.issuerUrl` / `cookieDomain` / `secureCookies` the same way.
  - Keep `d.config` for `secretKey`.
- Any test that calls `issueCsrfToken` or `sessionCookieOptions` directly: pass `ctx.services.settings.current()` (or an `EffectiveSettings` literal) instead of a `Config`.

- [ ] **Step 5: Run the tests**

Run: `npx vitest run tests/settings/live.test.ts`, then `npm test` and `npm run typecheck`.
Expected: all PASS. Existing tests are unchanged because `testConfig` locks all four settings to the config values.

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: read settings at use time and reload OIDC on change"
```

---

### Task 3: First-run setup (code, gate, /setup)

**Files:**
- Create: `src/setup/setup.ts`, `src/http/setup-routes.ts`, `views/setup.eta`
- Modify: `src/services.ts`, `src/http/app.ts`, `views/layout.eta`, `tests/helpers/app.ts`
- Test: `tests/http/setup.test.ts`

**Interfaces:**
- Consumes: `SettingsService` (Task 1), `applySettingsChange` (Task 2), `LoginRateLimiter` (`reserve(ip, identifier) → { blocked, ids }`, `release(ids)`), `usernameSchema`, `passwordSchema` (`src/api/common.ts`), `hashToken` (`src/crypto/secrets.ts`), `issueCsrfToken`/`verifyCsrfToken`, `sessionCookieOptions`, `SESSION_COOKIE`, `renderPage`.
- Produces:
  ```ts
  // src/setup/setup.ts
  export type SetupInput = { code: string; issuerUrl: string; username: string; email: string; password: string; passwordConfirm: string };
  export type SetupResult =
    | { ok: true; user: User; changed: SettingKey[] }
    | { ok: false; reason: 'rate_limited' | 'bad_code' | 'already_complete' }
    | { ok: false; reason: 'invalid'; fieldErrors: Record<string, string> };
  export class SetupService {
    constructor(s: Pick<Services, 'db' | 'users' | 'settings' | 'audit'>, limiter: LoginRateLimiter);
    isRequired(): Promise<boolean>;
    issueCode(): string;            // returns 'XXXX-XXXX-XXXX-XXXX'
    complete(input: SetupInput, ip: string): Promise<SetupResult>;
  }
  // src/services.ts — Services gains setup: SetupService
  // src/http/app.ts — BuildAppOptions gains setupGate?: boolean (default true), onRestart?: () => void
  // tests/helpers/app.ts — createTestContext(overrides, opts?: { setupGate?: boolean }) (default false)
  ```

- [ ] **Step 1: Write the failing setup tests**

`tests/http/setup.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, TEST_PASSWORD, type TestContext } from '../helpers/app.js';

let ctx: TestContext;
let code: string;
const cookie = (res: { cookies: unknown }, name: string) =>
  (res.cookies as Array<{ name: string; value: string }>).find((c) => c.name === name);

beforeEach(async () => {
  ctx = await createTestContext({ settingsFromEnv: new Set(), issuerUrl: 'http://localhost:9000' }, { setupGate: true });
  code = ctx.services.setup.issueCode();
});
afterEach(() => ctx.close());

async function form() {
  const res = await ctx.app.inject({ url: '/setup', headers: { 'x-forwarded-proto': 'https', host: 'auth.example.test' } });
  return { res, csrf: cookie(res, 'keystone_csrf')!.value };
}

async function submit(fields: Partial<Record<string, string>> = {}, ip = '10.1.1.1') {
  const { csrf } = await form();
  const body = {
    csrf,
    code,
    issuerUrl: 'https://auth.example.test',
    username: 'admin',
    email: 'admin@example.test',
    password: TEST_PASSWORD,
    passwordConfirm: TEST_PASSWORD,
    ...fields,
  };
  return ctx.app.inject({
    method: 'POST',
    url: '/setup',
    remoteAddress: ip,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(body as Record<string, string>).toString(),
    cookies: { keystone_csrf: csrf },
  });
}

describe('setup gate', () => {
  it('redirects pages to /setup and blocks API, OIDC and forward-auth while no user exists', async () => {
    expect((await ctx.app.inject({ url: '/' })).headers.location).toBe('/setup');
    expect((await ctx.app.inject({ url: '/login' })).headers.location).toBe('/setup');
    const api = await ctx.app.inject({ url: '/api/v1/users' });
    expect(api.statusCode).toBe(503);
    expect(api.headers['content-type']).toContain('application/problem+json');
    expect((await ctx.app.inject({ url: '/oidc/.well-known/openid-configuration' })).statusCode).toBe(503);
    expect((await ctx.app.inject({ url: '/outpost/auth' })).statusCode).toBe(503);
  });

  it('never blocks the health check', async () => {
    expect((await ctx.app.inject({ url: '/healthz' })).statusCode).toBe(200);
  });

  it('prefills the public URL from the request', async () => {
    const { res } = await form();
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('value="https://auth.example.test"');
  });
});

describe('POST /setup', () => {
  it('rejects a wrong code without creating anything', async () => {
    const res = await submit({ code: 'AAAA-AAAA-AAAA-AAAA' });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Setup code is incorrect');
    expect(await ctx.services.users.count()).toBe(0);
  });

  it('accepts the code in lowercase, without dashes and with spaces', async () => {
    const messy = ` ${code.replaceAll('-', '').toLowerCase()} `;
    const res = await submit({ code: messy });
    expect(res.statusCode).toBe(302);
  });

  it('blocks after 5 attempts from one IP', async () => {
    for (let i = 0; i < 5; i++) await submit({ code: 'WRONG-CODE' }, '10.9.9.9');
    const res = await submit({}, '10.9.9.9');
    expect(res.statusCode).toBe(429);
    expect(await ctx.services.users.count()).toBe(0);
  });

  it('shows field errors for bad input', async () => {
    const res = await submit({ username: 'a b', password: 'short', passwordConfirm: 'short' });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('use 2-64 letters');
    expect(res.body).toContain('at least 12 characters');
    expect(await ctx.services.users.count()).toBe(0);
  });

  it('rejects mismatched passwords', async () => {
    const res = await submit({ passwordConfirm: `${TEST_PASSWORD}x` });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Passwords do not match');
  });

  it('requires CSRF', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/setup',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ code }).toString(),
    });
    expect(res.statusCode).toBe(403);
  });

  it('creates the admin, saves the URL, signs in and closes setup', async () => {
    const res = await submit();
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/admin/settings');
    expect(cookie(res, 'keystone_session')).toBeDefined();
    const admin = await ctx.services.users.findByLogin('admin');
    expect(admin?.user.isAdmin).toBe(true);
    expect(ctx.services.settings.current().issuerUrl).toBe('https://auth.example.test');
    expect((await ctx.app.inject({ url: '/setup' })).statusCode).toBe(404);
    expect((await submit()).statusCode).toBe(404);
    expect((await ctx.app.inject({ url: '/oidc/.well-known/openid-configuration' })).json().issuer).toBe(
      'https://auth.example.test/oidc',
    );
  });

  it('lets only one of two concurrent setups succeed', async () => {
    const [a, b] = await Promise.all([submit({ username: 'admin1' }, '10.2.2.2'), submit({ username: 'admin2' }, '10.3.3.3')]);
    expect([a.statusCode, b.statusCode].sort()).toEqual([302, 404]);
    expect(await ctx.services.users.count()).toBe(1);
  });
});

describe('setup with locked public URL', () => {
  it('does not overwrite an env-provided issuer', async () => {
    await ctx.close();
    ctx = await createTestContext({ settingsFromEnv: new Set(['issuerUrl']), issuerUrl: 'https://env.example.test' }, { setupGate: true });
    code = ctx.services.setup.issueCode();
    const res = await submit({ issuerUrl: 'https://env.example.test' });
    expect(res.statusCode).toBe(302);
    expect(ctx.services.settings.current().issuerUrl).toBe('https://env.example.test');
  });
});
```
`findByLogin` returns `{ user, passwordHash }`. If its shape differs, check `src/identity/users.ts` and adapt the assertion. Fastify inject's `remoteAddress` sets `req.ip`.

- [ ] **Step 2: Run to see it fail**

Run: `npx vitest run tests/http/setup.test.ts`
Expected: FAIL, because `createTestContext` doesn't accept opts and `services.setup` is undefined.

- [ ] **Step 3: SetupService**

`src/setup/setup.ts`:
```ts
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import { passwordSchema, usernameSchema } from '../api/common.js';
import type { LoginRateLimiter } from '../auth/rate-limit.js';
import { hashToken } from '../crypto/secrets.js';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';
import type { SettingKey } from '../settings/keys.js';
import { SettingsValidationError } from '../settings/settings.js';

// Serialises setup against concurrent submissions (7_424_242–244 are taken by migrator, keys, bootstrap).
const LOCK_ID = 7_424_245;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export type SetupInput = {
  code: string;
  issuerUrl: string;
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
};

export type SetupResult =
  | { ok: true; user: User; changed: SettingKey[] }
  | { ok: false; reason: 'rate_limited' | 'bad_code' | 'already_complete' }
  | { ok: false; reason: 'invalid'; fieldErrors: Record<string, string> };

const normaliseCode = (code: string) => code.toUpperCase().replace(/[^A-Z0-9]/g, '');

export class SetupService {
  #codeHash: string | undefined;
  #complete = false;

  constructor(
    private readonly s: Pick<Services, 'db' | 'users' | 'settings' | 'audit'>,
    private readonly limiter: LoginRateLimiter,
  ) {}

  async isRequired(): Promise<boolean> {
    if (this.#complete) return false;
    if ((await this.s.users.count()) > 0) {
      this.#complete = true;
      this.#codeHash = undefined;
      return false;
    }
    return true;
  }

  issueCode(): string {
    const bytes = randomBytes(16);
    const raw = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
    this.#codeHash = hashToken(raw);
    return raw.match(/.{4}/g)!.join('-');
  }

  #codeMatches(code: string): boolean {
    if (!this.#codeHash) return false;
    const given = Buffer.from(hashToken(normaliseCode(code)), 'hex');
    const expected = Buffer.from(this.#codeHash, 'hex');
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  #validate(input: SetupInput): { errors: Record<string, string>; issuerUrl?: string } {
    const errors: Record<string, string> = {};
    const username = usernameSchema.safeParse(input.username.trim());
    if (!username.success) errors.username = username.error.issues[0]!.message;
    if (!z.email().safeParse(input.email.trim()).success) errors.email = 'Enter a valid email address';
    const password = passwordSchema.safeParse(input.password);
    if (!password.success) errors.password = password.error.issues[0]!.message;
    else if (input.password !== input.passwordConfirm) errors.passwordConfirm = 'Passwords do not match';
    let issuerUrl: string | undefined;
    if (!this.s.settings.isLocked('issuerUrl')) {
      try {
        issuerUrl = this.s.settings.validate({ issuerUrl: input.issuerUrl }).issuerUrl;
      } catch (e) {
        if (e instanceof SettingsValidationError) errors.issuerUrl = e.fieldErrors.issuerUrl ?? 'Invalid URL';
        else throw e;
      }
    }
    return { errors, ...(issuerUrl ? { issuerUrl } : {}) };
  }

  async complete(input: SetupInput, ip: string): Promise<SetupResult> {
    if (!(await this.isRequired())) return { ok: false, reason: 'already_complete' };
    const reservation = await this.limiter.reserve(`setup:${ip}`, 'setup');
    if (reservation.blocked) return { ok: false, reason: 'rate_limited' };
    if (!this.#codeMatches(input.code)) return { ok: false, reason: 'bad_code' };
    const { errors, issuerUrl } = this.#validate(input);
    if (Object.keys(errors).length > 0) {
      await this.limiter.release(reservation.ids);
      return { ok: false, reason: 'invalid', fieldErrors: errors };
    }
    const outcome = await this.s.db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
      if ((await this.s.users.count()) > 0) return null;
      const user = await this.s.users.create({
        username: input.username.trim(),
        email: input.email.trim(),
        password: input.password,
        isAdmin: true,
      });
      return user;
    });
    if (!outcome) {
      this.#complete = true;
      return { ok: false, reason: 'already_complete' };
    }
    this.#complete = true;
    this.#codeHash = undefined;
    await this.limiter.release(reservation.ids);
    const actor = { type: 'user', id: outcome.id } as const;
    const changed = issuerUrl ? await this.s.settings.update({ issuerUrl }, actor, ip) : [];
    await this.s.audit.record({ actor, action: 'setup.complete', target: outcome.id, ip });
    return { ok: true, user: outcome, changed };
  }
}
```
`users.create` runs on the pool while the transaction holds the lock. This is the same pattern as `src/bootstrap.ts`: the lock serialises the concurrent submissions, and the second one sees the committed user.

- [ ] **Step 4: Register SetupService**

In `src/services.ts`:
1. Import `SetupService` and add `setup: SetupService` to `Services`.
2. In `createServices`, create
```ts
const setup = new SetupService({ db, users, settings, audit }, new LoginRateLimiter(db, { maxPerIp: 5, maxPerUser: 1000 }));
```
3. Return `setup` from `createServices`.

- [ ] **Step 5: Gate and routes**

`src/http/setup-routes.ts`:
```ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { SESSION_COOKIE } from '../auth/sessions.js';
import { applySettingsChange, type Services } from '../services.js';
import { sessionCookieOptions } from './context.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

const FIELDS = ['code', 'issuerUrl', 'username', 'email', 'password', 'passwordConfirm'] as const;
type SetupBody = Partial<Record<(typeof FIELDS)[number] | 'csrf', unknown>>;
const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.split(',')[0]?.trim();

function detectedIssuer(req: FastifyRequest): string {
  const proto = first(req.headers['x-forwarded-proto']) || req.protocol;
  const host = first(req.headers['x-forwarded-host']) || req.headers.host || 'localhost:9000';
  return `${proto}://${host}`;
}

/** While no user exists, pages go to /setup and machine endpoints answer 503. Register before middie. */
export function registerSetupGate(app: FastifyInstance, s: Services): void {
  app.addHook('onRequest', async (req, reply) => {
    const path = req.url.split('?')[0] ?? '/';
    if (path === '/setup' || path === '/healthz') return;
    if (!(await s.setup.isRequired())) return;
    if (path.startsWith('/api/')) {
      return reply
        .code(503)
        .type('application/problem+json')
        .send({ type: 'about:blank', title: 'Setup required', status: 503, detail: 'Finish setup at /setup first.' });
    }
    if (path.startsWith('/oidc') || path.startsWith('/outpost/')) {
      return reply.code(503).send({ error: 'setup_required' });
    }
    return reply.redirect('/setup');
  });
}

export function registerSetupRoutes(app: FastifyInstance, s: Services): void {
  const render = (
    req: FastifyRequest,
    reply: FastifyReply,
    data: { values: Record<string, string>; errors?: Record<string, string>; error?: string | null },
  ) =>
    renderPage(reply, 'setup', {
      title: 'Set up Keystone',
      csrf: issueCsrfToken(req, reply, s.settings.current()),
      values: data.values,
      errors: data.errors ?? {},
      error: data.error ?? null,
      issuerLocked: s.settings.isLocked('issuerUrl'),
    });

  app.get('/setup', async (req, reply) => {
    if (!(await s.setup.isRequired())) return reply.callNotFound();
    const issuerUrl = s.settings.isLocked('issuerUrl') ? s.settings.current().issuerUrl : detectedIssuer(req);
    return render(req, reply, { values: { issuerUrl, username: 'admin', email: '' } });
  });

  app.post<{ Body: SetupBody }>('/setup', async (req, reply) => {
    if (!(await s.setup.isRequired())) return reply.callNotFound();
    const body = req.body ?? {};
    const str = (k: (typeof FIELDS)[number]) => (typeof body[k] === 'string' ? (body[k] as string) : '');
    const values = { issuerUrl: str('issuerUrl'), username: str('username'), email: str('email') };
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return render(req, reply, { values, error: 'The form expired. Please try again.' });
    }
    const result = await s.setup.complete(
      {
        code: str('code'),
        issuerUrl: s.settings.isLocked('issuerUrl') ? s.settings.current().issuerUrl : values.issuerUrl,
        username: values.username,
        email: values.email,
        password: str('password'),
        passwordConfirm: str('passwordConfirm'),
      },
      req.ip,
    );
    if (!result.ok) {
      if (result.reason === 'already_complete') return reply.callNotFound();
      if (result.reason === 'rate_limited') {
        reply.code(429);
        return render(req, reply, { values, error: 'Too many attempts. Try again in 15 minutes.' });
      }
      reply.code(400);
      if (result.reason === 'bad_code') return render(req, reply, { values, error: 'Setup code is incorrect.' });
      return render(req, reply, { values, errors: result.fieldErrors });
    }
    await applySettingsChange(s, result.changed);
    const { token } = await s.sessions.create(result.user.id, {
      ip: req.ip,
      ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
    });
    reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions(s.settings.current(), s.sessions.ttlSeconds));
    return reply.redirect('/admin/settings');
  });
}
```

In `src/http/app.ts`:
1. Add `setupGate?: boolean; onRestart?: () => void;` to `BuildAppOptions`.
2. Import `registerSetupGate` and `registerSetupRoutes`.
3. Right after `await app.register(formbody);` and before `await app.register(middie);`, add:
```ts
  if (opts.setupGate ?? true) registerSetupGate(app, s);
```
4. Next to `registerLoginRoutes(app, s);`, add `registerSetupRoutes(app, s);`.

If `/oidc` still answers 200 during setup in the gate test, middie's hook is running first. Move the gate registration above `await app.register(cookie);` and re-run the test.

In `tests/helpers/app.ts`, change `createTestContext` to `createTestContext(overrides: Partial<Config> = {}, opts: { setupGate?: boolean } = {})` and build with `buildApp(services, { setupGate: opts.setupGate ?? false })`.

- [ ] **Step 6: Setup view**

`views/setup.eta`:
```html
<% layout('layout') %>
<h1>Set up Keystone</h1>
<p class="muted">Find the setup code in the container log: <code>docker compose logs keystone</code></p>
<% if (it.error) { %><p class="error" role="alert"><%= it.error %></p><% } %>
<form method="post" action="/setup">
  <input type="hidden" name="csrf" value="<%= it.csrf %>">
  <label for="code">Setup code</label>
  <input id="code" name="code" autocomplete="off" placeholder="XXXX-XXXX-XXXX-XXXX" required autofocus>
  <label for="issuerUrl">Public URL</label>
  <input id="issuerUrl" name="issuerUrl" value="<%= it.values.issuerUrl %>" <%= it.issuerLocked ? 'disabled' : 'required' %>>
  <% if (it.issuerLocked) { %><p class="muted">Set by KEYSTONE_ISSUER_URL</p><% } %>
  <% if (it.errors.issuerUrl) { %><p class="error"><%= it.errors.issuerUrl %></p><% } %>
  <p class="muted">The address people open in the browser, for example https://auth.example.com.</p>
  <label for="username">Admin username</label>
  <input id="username" name="username" value="<%= it.values.username %>" autocomplete="username" required>
  <% if (it.errors.username) { %><p class="error"><%= it.errors.username %></p><% } %>
  <label for="email">Email</label>
  <input id="email" name="email" type="email" value="<%= it.values.email %>" autocomplete="email" required>
  <% if (it.errors.email) { %><p class="error"><%= it.errors.email %></p><% } %>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required>
  <% if (it.errors.password) { %><p class="error"><%= it.errors.password %></p><% } %>
  <label for="passwordConfirm">Repeat password</label>
  <input id="passwordConfirm" name="passwordConfirm" type="password" autocomplete="new-password" required>
  <% if (it.errors.passwordConfirm) { %><p class="error"><%= it.errors.passwordConfirm %></p><% } %>
  <button type="submit">Create admin and finish setup</button>
</form>
```
In `views/layout.eta`, add `code { font-family: ui-monospace, monospace; font-size: .875em; }` to the `<style>` block.

- [ ] **Step 7: Run the tests**

Run: `npx vitest run tests/http/setup.test.ts`, then `npm test` and `npm run typecheck`.
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add src tests views
git commit -m "feat: add first-run setup with one-time code"
```

---

### Task 4: Admin layout, Settings page and restart

**Files:**
- Create: `src/http/admin-guard.ts`, `src/http/admin-routes.ts`, `views/admin/layout.eta`, `views/admin/settings.eta`, `views/admin/restarting.eta`
- Modify: `src/http/app.ts`, `views/home.eta`
- Test: `tests/http/admin.test.ts`

**Interfaces:**
- Consumes: `currentUser` (`src/http/context.ts`), `SettingsService.describe/update`, `SettingsValidationError`, `applySettingsChange`, `BuildAppOptions.onRestart` (Task 3), `renderPage`, CSRF helpers.
- Produces:
  ```ts
  // src/http/admin-guard.ts
  export async function requireAdmin(req: FastifyRequest, reply: FastifyReply, s: Services): Promise<User | null>; // null = reply already sent
  // src/http/admin-routes.ts
  export function registerAdminRoutes(app: FastifyInstance, s: Services, opts: { onRestart?: () => void }): void;
  ```

- [ ] **Step 1: Write the failing admin tests**

`tests/http/admin.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildApp } from '../../src/http/app.js';
import { createTestContext, TEST_PASSWORD, type TestContext } from '../helpers/app.js';

let ctx: TestContext;
const cookie = (res: { cookies: unknown }, name: string) =>
  (res.cookies as Array<{ name: string; value: string; domain?: string }>).find((c) => c.name === name);
const form = (fields: Record<string, string>) => new URLSearchParams(fields).toString();

beforeEach(async () => {
  ctx = await createTestContext({ settingsFromEnv: new Set(['trustProxy']), issuerUrl: 'http://127.0.0.1:9000' });
  await ctx.services.users.create({ username: 'root', password: TEST_PASSWORD, isAdmin: true });
  await ctx.services.users.create({ username: 'bob', password: TEST_PASSWORD });
});
afterEach(() => ctx.close());

async function signIn(app = ctx.app, username = 'root') {
  const page = await app.inject({ url: '/login' });
  const csrf = cookie(page, 'keystone_csrf')!.value;
  const res = await app.inject({
    method: 'POST',
    url: '/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: form({ csrf, rd: '/', identifier: username, password: TEST_PASSWORD }),
    cookies: { keystone_csrf: csrf },
  });
  return { keystone_csrf: csrf, keystone_session: cookie(res, 'keystone_session')!.value };
}

function save(cookies: Record<string, string>, fields: Record<string, string>, app = ctx.app) {
  return app.inject({
    method: 'POST',
    url: '/admin/settings',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: form({ csrf: cookies.keystone_csrf!, ...fields }),
    cookies,
  });
}

describe('admin settings', () => {
  it('redirects signed-out visitors to login', async () => {
    const res = await ctx.app.inject({ url: '/admin/settings' });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/login?rd=%2Fadmin%2Fsettings');
  });

  it('forbids non-admins', async () => {
    const cookies = await signIn(ctx.app, 'bob');
    expect((await ctx.app.inject({ url: '/admin/settings', cookies })).statusCode).toBe(403);
    expect((await save(cookies, { logLevel: 'debug' })).statusCode).toBe(403);
  });

  it('shows the form with locked fields marked', async () => {
    const cookies = await signIn();
    const res = await ctx.app.inject({ url: '/admin/settings', cookies });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Set by KEYSTONE_TRUST_PROXY');
    expect(res.body).toContain('value="http://127.0.0.1:9000"');
  });

  it('saves valid settings and applies them live', async () => {
    const cookies = await signIn();
    const res = await save(cookies, { issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test', logLevel: 'debug' });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain('/admin/settings?saved=1');
    expect(res.headers.location).toContain('issuer=1');
    expect(ctx.services.settings.current()).toMatchObject({ issuerUrl: 'https://auth.example.test', logLevel: 'debug' });
    expect((await ctx.app.inject({ url: '/oidc/.well-known/openid-configuration' })).json().issuer).toBe(
      'https://auth.example.test/oidc',
    );
    const page = await ctx.app.inject({ url: res.headers.location as string, cookies });
    expect(page.body).toContain('Saved');
    expect(page.body).toContain('https://auth.example.test/oidc');
  });

  it('re-renders with field errors and saves nothing on invalid input', async () => {
    const cookies = await signIn();
    const res = await save(cookies, { issuerUrl: 'https://auth.example.test/path', logLevel: 'debug' });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('must not contain a path');
    expect(ctx.services.settings.current().logLevel).toBe('silent');
  });

  it('rejects a crafted change to a locked field', async () => {
    const cookies = await signIn();
    const res = await save(cookies, { trustProxy: 'true' });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Set by KEYSTONE_TRUST_PROXY');
  });

  it('requires CSRF', async () => {
    const cookies = await signIn();
    const res = await save({ ...cookies, keystone_csrf: 'x'.repeat(32) }, { logLevel: 'debug' });
    expect(res.statusCode).toBe(403);
  });
});

describe('restart', () => {
  it('requires an admin and CSRF, records audit, then calls onRestart after responding', async () => {
    const onRestart = vi.fn();
    const app = await buildApp(ctx.services, { setupGate: false, onRestart });
    const cookies = await signIn(app);
    const bad = await app.inject({
      method: 'POST',
      url: '/admin/restart',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: form({ csrf: 'nope' }),
      cookies,
    });
    expect(bad.statusCode).toBe(403);
    expect(onRestart).not.toHaveBeenCalled();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/restart',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: form({ csrf: cookies.keystone_csrf }),
      cookies,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('http-equiv="refresh"');
    await vi.waitFor(() => expect(onRestart).toHaveBeenCalledTimes(1));
    const audit = await ctx.services.db.selectFrom('audit_log').select('action').where('action', '=', 'system.restart').execute();
    expect(audit).toHaveLength(1);
    await app.close();
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npx vitest run tests/http/admin.test.ts`
Expected: FAIL with 404 on `/admin/settings`.

- [ ] **Step 3: Guard**

`src/http/admin-guard.ts`:
```ts
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';
import { currentUser } from './context.js';
import { renderPage } from './views.js';

/** Returns the signed-in admin, or sends a redirect (signed out) / 403 page (not an admin) and returns null. */
export async function requireAdmin(req: FastifyRequest, reply: FastifyReply, s: Services): Promise<User | null> {
  const user = await currentUser(req, s);
  if (!user) {
    const path = req.url.split('?')[0] ?? '/';
    await reply.redirect(`/login?rd=${encodeURIComponent(path)}`);
    return null;
  }
  if (!user.isAdmin) {
    reply.code(403);
    await renderPage(reply, 'error', { title: 'Forbidden', message: 'You need an administrator account to open this page.' });
    return null;
  }
  return user;
}
```

- [ ] **Step 4: Admin routes**

`src/http/admin-routes.ts`:
```ts
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { SETTING_KEYS, type SettingKey } from '../settings/keys.js';
import { SettingsValidationError, type SettingsPatch } from '../settings/settings.js';
import { LOG_LEVELS } from '../settings/keys.js';
import { applySettingsChange, type Services } from '../services.js';
import type { User } from '../identity/users.js';
import { requireAdmin } from './admin-guard.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

type Body = Partial<Record<SettingKey | 'csrf', unknown>>;

const HELP: Record<SettingKey, string> = {
  issuerUrl: 'The address people open, e.g. https://auth.example.com. Apps use <public URL>/oidc as issuer.',
  cookieDomain: 'Optional. A parent domain such as example.com lets one sign-in cover all its subdomains (forward auth).',
  trustProxy: 'Which proxies may set X-Forwarded-* headers: IPs, CIDR ranges, loopback, linklocal, uniquelocal, or true/false.',
  logLevel: 'How much Keystone writes to its log.',
};
const LABELS: Record<SettingKey, string> = {
  issuerUrl: 'Public URL',
  cookieDomain: 'Cookie domain',
  trustProxy: 'Trusted proxies',
  logLevel: 'Log level',
};

export function registerAdminRoutes(app: FastifyInstance, s: Services, opts: { onRestart?: () => void }): void {
  const render = (
    req: FastifyRequest,
    reply: FastifyReply,
    user: User,
    data: { values?: Partial<Record<SettingKey, string>>; errors?: Partial<Record<SettingKey, string>>; notices?: string[]; restart?: boolean },
  ) =>
    renderPage(reply, 'admin/settings', {
      title: 'Settings',
      user,
      active: 'settings',
      csrf: issueCsrfToken(req, reply, s.settings.current()),
      fields: s.settings.describe().map((f) => ({
        ...f,
        label: LABELS[f.key],
        help: HELP[f.key],
        value: data.values?.[f.key] ?? f.value,
        error: data.errors?.[f.key] ?? null,
      })),
      logLevels: LOG_LEVELS,
      notices: data.notices ?? [],
      restart: data.restart ?? false,
    });

  app.get('/admin', async (_req, reply) => reply.redirect('/admin/settings'));

  app.get<{ Querystring: Record<string, string | undefined> }>('/admin/settings', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    const q = req.query;
    const notices: string[] = [];
    if (q.saved === '1') notices.push(q.restart === '1' ? 'Saved — restart Keystone to apply trusted proxies.' : 'Saved.');
    if (q.issuer === '1') {
      notices.push(`Connected apps must update their issuer to ${s.settings.current().issuerUrl}/oidc.`);
    }
    if (q.cookie === '1') notices.push('Cookie domain changed: people may need to sign in again.');
    if (q.oidc === 'failed') notices.push('Saved, but the OIDC endpoint could not be reloaded — see the logs.');
    return render(req, reply, user, { notices, restart: q.restart === '1' });
  });

  app.post<{ Body: Body }>('/admin/settings', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    const body = req.body ?? {};
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return renderPage(reply, 'error', { title: 'Forbidden', message: 'The form expired. Reload the page and try again.' });
    }
    const patch: SettingsPatch = {};
    for (const key of SETTING_KEYS) {
      const v = body[key];
      if (typeof v === 'string') patch[key] = v;
    }
    let changed: SettingKey[];
    try {
      changed = await s.settings.update(patch, { type: 'user', id: user.id }, req.ip);
    } catch (err) {
      if (!(err instanceof SettingsValidationError)) throw err;
      reply.code(400);
      return render(req, reply, user, { values: patch, errors: err.fieldErrors });
    }
    const { oidcReloadFailed } = await applySettingsChange(s, changed);
    if (changed.includes('logLevel')) app.log.level = s.settings.current().logLevel;
    const q = new URLSearchParams({ saved: '1' });
    if (changed.includes('trustProxy')) q.set('restart', '1');
    if (changed.includes('issuerUrl')) q.set('issuer', '1');
    if (changed.includes('cookieDomain')) q.set('cookie', '1');
    if (oidcReloadFailed) q.set('oidc', 'failed');
    return reply.redirect(`/admin/settings?${q.toString()}`);
  });

  app.post<{ Body: Body }>('/admin/restart', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    if (!verifyCsrfToken(req, (req.body ?? {}).csrf)) {
      reply.code(403);
      return renderPage(reply, 'error', { title: 'Forbidden', message: 'The form expired. Reload the page and try again.' });
    }
    await s.audit.record({ actor: { type: 'user', id: user.id }, action: 'system.restart', ip: req.ip });
    if (opts.onRestart) reply.raw.once('finish', () => setImmediate(opts.onRestart!));
    return renderPage(reply, 'admin/restarting', { title: 'Restarting', canRestart: Boolean(opts.onRestart) });
  });
}
```
Check `User` has `isAdmin` and `displayName` (`src/identity/users.ts`). If not, use the actual field names in the guard and views.

In `src/http/app.ts`, import `registerAdminRoutes` and add `registerAdminRoutes(app, s, { ...(opts.onRestart ? { onRestart: opts.onRestart } : {}) });` after `registerSetupRoutes`.

- [ ] **Step 5: Views**

`views/admin/layout.eta`:
```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<% if (it.refresh) { %><meta http-equiv="refresh" content="<%= it.refresh %>"><% } %>
<title><%= it.title %> · Keystone</title>
<style>
:root { color-scheme: light dark; --bg:#f5f6f8; --surface:#fff; --surface2:#f0f2f5; --line:#e2e5ea; --fg:#171b22; --muted:#586172; --accent:#2b59e8; --accent-soft:#e9efff; --ok:#18794e; --ok-soft:#e2f4ea; --warn:#9a5b00; --warn-soft:#fdf0d9; --danger:#c0362c; }
@media (prefers-color-scheme: dark) { :root { --bg:#0e1116; --surface:#161a21; --surface2:#1d222b; --line:#272d38; --fg:#e7eaf0; --muted:#a2aab8; --accent:#7092ff; --accent-soft:#1b2546; --ok:#4fc68f; --ok-soft:#12291e; --warn:#f0b34e; --warn-soft:#2e230f; --danger:#f2766b; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, 'Segoe UI', sans-serif; }
.top { display:flex; align-items:center; gap:12px; height:56px; padding:0 max(16px, env(safe-area-inset-left)); background:var(--surface); border-bottom:1px solid var(--line); }
.brand { display:flex; align-items:center; gap:8px; font-weight:700; font-size:17px; color:var(--fg); text-decoration:none; }
.brand svg { width:22px; height:22px; fill:var(--accent); }
.top .who { margin-left:auto; display:flex; align-items:center; gap:12px; color:var(--muted); font-size:14px; }
.top form { margin:0; }
.shell { display:grid; grid-template-columns:220px minmax(0,1fr); min-height:calc(100vh - 56px); }
nav { background:var(--surface); border-right:1px solid var(--line); padding:20px 12px; }
nav .cap { margin:0 10px 6px; color:var(--muted); font-size:11px; font-weight:600; letter-spacing:.07em; text-transform:uppercase; }
nav a { display:block; padding:8px 10px; border-radius:6px; color:var(--muted); text-decoration:none; font-weight:500; }
nav a.active { background:var(--accent-soft); color:var(--accent); font-weight:600; }
main { padding:32px clamp(16px,4vw,40px) 56px; min-width:0; }
.page { max-width:720px; margin:0 auto; display:grid; gap:20px; }
h1 { margin:0; font-size:26px; }
.panel { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:20px; }
.field { display:grid; gap:6px; padding:14px 0; border-top:1px solid var(--line); }
.field:first-child { border-top:0; padding-top:0; }
label { font-weight:600; font-size:14px; }
input, select { width:100%; height:40px; padding:0 12px; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:inherit; font:inherit; }
input:disabled, select:disabled { background:var(--surface2); color:var(--muted); }
.help { margin:0; color:var(--muted); font-size:13px; }
.lock { color:var(--warn); font-size:13px; font-weight:600; }
.error { margin:0; color:var(--danger); font-size:13px; }
.notice { margin:0; padding:10px 12px; border-radius:6px; background:var(--ok-soft); color:var(--ok); }
.notice.warn { background:var(--warn-soft); color:var(--warn); }
button { height:40px; padding:0 16px; border:0; border-radius:6px; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
button.secondary { background:var(--surface); color:var(--fg); border:1px solid var(--line); }
.actions { display:flex; gap:8px; flex-wrap:wrap; padding-top:16px; }
@media (max-width:760px) { .shell { grid-template-columns:minmax(0,1fr); } nav { border-right:0; border-bottom:1px solid var(--line); display:flex; gap:4px; padding:8px 12px; } nav .cap { display:none; } }
</style>
</head>
<body>
<header class="top">
  <a class="brand" href="/admin/settings"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 4h18l-3.6 16H6.6z"/></svg>Keystone</a>
  <div class="who"><span><%= it.user.username %></span><form method="post" action="/logout"><button class="secondary" type="submit">Sign out</button></form></div>
</header>
<div class="shell">
  <nav aria-label="Admin"><p class="cap">Admin</p><a href="/admin/settings" class="<%= it.active === 'settings' ? 'active' : '' %>">Settings</a></nav>
  <main><div class="page"><%~ it.body %></div></main>
</div>
</body>
</html>
```

`views/admin/settings.eta`:
```html
<% layout('admin/layout') %>
<h1>Settings</h1>
<% it.notices.forEach(function (n) { %><p class="notice<%= n.indexOf('Saved.') === 0 ? '' : ' warn' %>" role="status"><%= n %></p><% }) %>
<% if (it.restart) { %>
<form method="post" action="/admin/restart"><input type="hidden" name="csrf" value="<%= it.csrf %>"><button type="submit">Restart Keystone</button></form>
<% } %>
<form class="panel" method="post" action="/admin/settings">
  <input type="hidden" name="csrf" value="<%= it.csrf %>">
  <% it.fields.forEach(function (f) { %>
  <div class="field">
    <label for="<%= f.key %>"><%= f.label %></label>
    <% if (f.key === 'logLevel') { %>
      <select id="logLevel" name="logLevel" <%= f.locked ? 'disabled' : '' %>>
        <% it.logLevels.forEach(function (l) { %><option value="<%= l %>" <%= l === f.value ? 'selected' : '' %>><%= l %></option><% }) %>
      </select>
    <% } else { %>
      <input id="<%= f.key %>" name="<%= f.key %>" value="<%= f.value %>" <%= f.locked ? 'disabled' : '' %>>
    <% } %>
    <% if (f.locked) { %><p class="lock">Set by <%= f.envVar %></p><% } %>
    <% if (f.error) { %><p class="error" role="alert"><%= f.error %></p><% } %>
    <p class="help"><%= f.help %></p>
  </div>
  <% }) %>
  <div class="actions"><button type="submit">Save settings</button></div>
</form>
```
Disabled inputs are not submitted, so locked keys never appear in a normal POST. A crafted POST with a locked key is rejected by `SettingsService.validate`.

`views/admin/restarting.eta`:
```html
<% layout('admin/layout', { ...it, refresh: '6;url=/admin/settings', active: 'settings' }) %>
<h1>Restarting Keystone</h1>
<% if (it.canRestart) { %>
<p class="notice">Keystone is restarting. This page reloads in a few seconds.</p>
<% } else { %>
<p class="notice warn">Keystone is not running under a supervisor here. Start it again manually.</p>
<% } %>
```
Check how Eta 4 passes data to a layout. If `layout('admin/layout', {...})` does not merge, set `refresh` in the route data instead (`renderPage(..., { title, user, refresh: '6;url=/admin/settings', ... })`) and call plain `layout('admin/layout')`. The route must pass `user` either way.

In `views/home.eta`, after the "Signed in as" line, add:
```html
<% if (it.user.isAdmin) { %><p><a href="/admin/settings">Admin settings</a></p><% } %>
```

- [ ] **Step 6: Run the tests**

Run: `npx vitest run tests/http/admin.test.ts`, then `npm test` and `npm run typecheck`.
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src views tests
git commit -m "feat: add admin settings page and restart"
```

---

### Task 5: Server wiring, Docker docs and smoke test

**Files:**
- Modify: `src/server.ts`, `docker-compose.yml`, `README.md`, `.env.example`

**Interfaces:**
- Consumes: `services.settings.current()`, `services.setup.isRequired/issueCode`, `BuildAppOptions.onRestart`, the existing `shutdown()` in `src/server.ts`.
- Produces: the production entry point. No new exports.

- [ ] **Step 1: server.ts**

In `src/server.ts`:
1. Build the app with the effective log level and the restart hook. Replace the `buildApp` line:
```ts
const app = await buildApp(services, {
  logger: { level: services.settings.current().logLevel },
  onRestart: () => {
    app.log.info('restart requested from admin settings');
    void shutdown()
      .catch((err) => app.log.error({ err }, 'shutdown failed'))
      .finally(() => process.exit(0));
  },
});
```
   `shutdown` is a function declaration below this line, so it is hoisted. Keep it as a `function` declaration.
2. After the `ensureBootstrapAdmin` block, add:
```ts
if (await services.setup.isRequired()) {
  const code = services.setup.issueCode();
  app.log.warn(`Keystone setup code: ${code} — open ${services.settings.current().issuerUrl}/setup`);
}
```

- [ ] **Step 2: Compose comments**

In `docker-compose.yml`, above the `keystone` service's env pass-through lines (`KEYSTONE_ISSUER_URL`, `KEYSTONE_COOKIE_DOMAIN`, `KEYSTONE_TRUST_PROXY`, `LOG_LEVEL`, `KEYSTONE_BOOTSTRAP_ADMIN_*`, `KEYSTONE_SECRET_KEY`), add:
```yaml
      # All optional. Normally set the public URL, cookie domain, trusted proxies and log level in
      # Keystone's Settings page (/admin/settings); a value set here overrides it and is shown locked.
```
If `KEYSTONE_ISSUER_URL` has a non-empty default (e.g. `${KEYSTONE_ISSUER_URL:-http://localhost:9000}`), change it to `${KEYSTONE_ISSUER_URL:-}`. Otherwise it would always count as set by the environment and lock the field. Apply the same to `KEYSTONE_TRUST_PROXY`, `KEYSTONE_COOKIE_DOMAIN` and `LOG_LEVEL`. `loadConfig` already treats empty strings as unset.

- [ ] **Step 3: README and .env.example**

Rewrite the README "Start" section to this flow:
```markdown
## Start

No `.env` file is needed.

1. `docker compose up -d --build`
2. `docker compose logs keystone` and copy the line `Keystone setup code: XXXX-XXXX-XXXX-XXXX`
3. Open `http://<host>:9000/setup` (or your public URL through the reverse proxy), enter the code,
   the public URL and the first admin account.
4. You land on **Settings** (`/admin/settings`) where you can change the public URL, cookie
   domain, trusted proxies and log level at any time.

A new setup code is printed on every start until setup is finished. Trusted-proxy changes need a
restart (Settings shows a **Restart Keystone** button); everything else applies immediately.
```
Move every env-var explanation into a new section, `## Advanced: environment overrides`. State there that any of these variables, when set, overrides the Settings page and shows the field as locked. Keep the existing content about backups, the reverse proxy, OIDC, forward-auth and the API.

Replace the header of `.env.example` with:
```sh
# Optional. Keystone needs no .env: use the setup screen and Settings page instead.
# Anything set here overrides the matching setting and is shown locked in the UI.
```

- [ ] **Step 4: Verify the full suite and build**

Run: `npm test`, `npm run typecheck`, `npm run build`
Expected: all pass, and `dist/server.js` exists.

- [ ] **Step 5: Docker smoke test (isolated project, no .env)**

Never use the default project. From the repo root:
```bash
test ! -e .env || { echo ".env exists — skip smoke test and report"; exit 1; }
KEYSTONE_HOST_PORT=19000 docker compose -p keystone-smoke up -d --build --wait
CODE=$(docker compose -p keystone-smoke logs keystone 2>/dev/null | grep -o 'setup code: [A-Z0-9-]*' | tail -1 | cut -d' ' -f3)
echo "code=$CODE"
curl -fsS http://127.0.0.1:19000/healthz
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://127.0.0.1:19000/
```
Expected:
- the code is printed;
- healthz returns `{"status":"ok"}`;
- `/` returns `302 .../setup`.

Complete setup with curl:
1. `GET /setup` with a cookie jar (`-c jar -b jar`) and extract the `csrf` hidden input value.
2. `POST /setup` with `code`, `issuerUrl=http://localhost:19000`, `username=admin`, `email=admin@example.test`, `password=smoke-test-password-123`, `passwordConfirm` (the same), and `csrf`.

Expected:
- `302` to `/admin/settings`;
- `curl -s http://127.0.0.1:19000/oidc/.well-known/openid-configuration` shows `"issuer":"http://localhost:19000/oidc"`;
- after a `docker compose -p keystone-smoke restart keystone`, no new setup code is logged and settings persist.

Then always clean up:
```bash
docker compose -p keystone-smoke down -v
```
Record the actual outputs in your report.

- [ ] **Step 6: Commit**

```bash
git add src/server.ts docker-compose.yml README.md .env.example
git commit -m "feat: log setup code, wire restart, document .env-free deploy"
```
