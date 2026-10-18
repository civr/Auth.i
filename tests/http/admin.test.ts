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
    const res = await save({ ...cookies, keystone_csrf: 'x'.repeat(32) }, { csrf: 'y'.repeat(32), logLevel: 'debug' });
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
