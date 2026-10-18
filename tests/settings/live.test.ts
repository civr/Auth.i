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
