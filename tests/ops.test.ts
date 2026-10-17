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

  it('creates exactly one admin when instances start concurrently', async () => {
    const results = await Promise.all([ensureBootstrapAdmin(ctx.services), ensureBootstrapAdmin(ctx.services)]);
    expect(results.sort()).toEqual(['created', 'skipped']);
    expect(await ctx.services.users.count()).toBe(1);
  });

  it('rejects an invalid bootstrap username without creating a user', async () => {
    const services = {
      ...ctx.services,
      config: { ...ctx.services.config, bootstrapAdmin: { username: 'bad name!', password: TEST_PASSWORD } },
    };
    await expect(ensureBootstrapAdmin(services)).rejects.toThrow(/KEYSTONE_BOOTSTRAP_ADMIN_USER/);
    expect(await ctx.services.users.count()).toBe(0);
  });

  it('rejects a short bootstrap password', async () => {
    const services = {
      ...ctx.services,
      config: { ...ctx.services.config, bootstrapAdmin: { username: 'admin', password: 'short' } },
    };
    await expect(ensureBootstrapAdmin(services)).rejects.toThrow(/KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD/);
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
    const token = out.match(/keystone_[A-Za-z0-9_-]+/)![0];
    expect(await ctx.services.apiTokens.verify(token)).not.toBeNull();
  });

  it('creates an admin with a generated password', async () => {
    const out = await runCommand(ctx.services, ['create-admin', 'root', 'root@example.test']);
    const password = out.match(/Password: (\S+)/)![1]!;
    expect(password.length).toBeGreaterThanOrEqual(12);
    const result = await ctx.services.localAuth.authenticate('root', password, '127.0.0.1');
    expect(result.ok && result.user.isAdmin).toBe(true);
  });

  it('rejects an invalid admin username', async () => {
    await expect(runCommand(ctx.services, ['create-admin', 'x'])).rejects.toThrow(/username/i);
    await expect(runCommand(ctx.services, ['create-admin', 'bad name'])).rejects.toThrow(/username/i);
    expect(await ctx.services.users.count()).toBe(0);
  });

  it('resets a password and ends sessions', async () => {
    const user = await ctx.services.users.create({ username: 'alice', password: TEST_PASSWORD });
    const { token } = await ctx.services.sessions.create(user.id);
    const out = await runCommand(ctx.services, ['reset-password', 'ALICE']);
    const password = out.match(/Password: (\S+)/)![1]!;
    expect((await ctx.services.localAuth.authenticate('alice', password, '127.0.0.1')).ok).toBe(true);
    expect(await ctx.services.sessions.validate(token)).toBeNull();
  });

  it('reset-password clears login rate-limit attempts for username and email', async () => {
    const user = await ctx.services.users.create({ username: 'alice', email: 'alice@example.test', password: TEST_PASSWORD });
    for (let i = 0; i < 3; i++) {
      await ctx.services.limiter.reserve('9.9.9.9', 'alice');
      await ctx.services.limiter.reserve('9.9.9.9', 'alice@example.test');
    }
    await runCommand(ctx.services, ['reset-password', user.username]);
    const rows = await ctx.services.db.selectFrom('login_attempts').select('key').where('key', 'like', 'user:%').execute();
    expect(rows).toEqual([]);
  });

  it('reports usage and errors', async () => {
    expect(await runCommand(ctx.services, [])).toBe(USAGE);
    await expect(runCommand(ctx.services, ['create-api-token'])).rejects.toThrow(/Usage/);
    await expect(runCommand(ctx.services, ['reset-password', 'nobody'])).rejects.toThrow(/not found/);
  });
});
