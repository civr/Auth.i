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
  // After setup completes /setup is 404 and issues no CSRF cookie; fall back to a dummy token so the POST reaches the 404 path.
  return { res, csrf: cookie(res, 'keystone_csrf')?.value ?? 'x'.repeat(32) };
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

  it('does not let one IP block setup for another', async () => {
    for (let i = 0; i < 6; i++) await submit({ code: 'WRONG-CODE' }, '10.7.7.7');
    const res = await submit({}, '10.8.8.8');
    expect(res.statusCode).toBe(302);
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
