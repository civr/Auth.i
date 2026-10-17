import type { Response as InjectResponse } from 'light-my-request';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDb } from '../../src/db/db.js';
import { buildApp } from '../../src/http/app.js';
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
  return { res, csrf: cookie(res, 'keystone_csrf')!.value };
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
  return postLogin({ csrf, rd, identifier: 'alice', password: TEST_PASSWORD }, { keystone_csrf: csrf });
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
    expect(cookie(res, 'keystone_session')).toBeUndefined();
  });

  it('shows an error for wrong credentials and keeps the identifier', async () => {
    const { csrf } = await loginForm();
    const res = await postLogin({ csrf, identifier: 'alice', password: 'wrong-password-1' }, { keystone_csrf: csrf });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('Invalid username or password.');
    expect(res.body).toContain('value="alice"');
  });

  it('signs in, sets a secure session cookie on the cookie domain and shows the home page', async () => {
    const res = await signIn();
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/');
    const session = cookie(res, 'keystone_session')!;
    expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Lax', domain: '.example.test', path: '/' });
    const home = await ctx.app.inject({ method: 'GET', url: '/', cookies: { keystone_session: session.value } });
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
    const token = cookie(await signIn(), 'keystone_session')!.value;
    const res = await ctx.app.inject({ method: 'GET', url: '/login?rd=%2Fnext', cookies: { keystone_session: token } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/next');
  });

  it('signs out and invalidates the session', async () => {
    const token = cookie(await signIn(), 'keystone_session')!.value;
    const res = await ctx.app.inject({ method: 'POST', url: '/logout', cookies: { keystone_session: token } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/login?loggedOut=1');
    expect(cookie(res, 'keystone_session')?.value).toBe('');
    expect(await ctx.services.sessions.validate(token)).toBeNull();
    const home = await ctx.app.inject({ method: 'GET', url: '/', cookies: { keystone_session: token } });
    expect(home.headers.location).toBe('/login');
  });

  it('answers 429 when rate limited', async () => {
    const { csrf } = await loginForm();
    let res: InjectResponse | undefined;
    for (let i = 0; i < 11; i++) {
      res = await postLogin({ csrf, identifier: 'alice', password: 'wrong-password-1' }, { keystone_csrf: csrf });
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

describe('extra behaviours', () => {
  it('shows the same error for an inactive account as for a wrong password', async () => {
    const user = await ctx.services.users.findByLogin('alice');
    await ctx.services.users.update(user!.user.id, { isActive: false });
    const { csrf } = await loginForm();
    const res = await postLogin({ csrf, identifier: 'alice', password: TEST_PASSWORD }, { keystone_csrf: csrf });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('Invalid username or password.');
    expect(cookie(res, 'keystone_session')).toBeUndefined();
  });

  it('sets a 12 hour max-age on the session cookie', async () => {
    const session = cookie(await signIn(), 'keystone_session')!;
    expect(session.maxAge).toBe(43200);
  });

  it('rejects repeated form fields with the invalid-credentials page, not a 500', async () => {
    const { csrf } = await loginForm();
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `csrf=${csrf}&identifier=alice&identifier=bob&password=${TEST_PASSWORD}&password=x`,
      cookies: { keystone_csrf: csrf },
    });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('Invalid username or password.');
  });

  it('answers /healthz with 503 when the database is unreachable', async () => {
    const bad = createDb('postgres://nobody:nope@127.0.0.1:1/none');
    const app = await buildApp({ ...ctx.services, db: bad });
    try {
      const res = await app.inject({ method: 'GET', url: '/healthz' });
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ status: 'unavailable' });
    } finally {
      await app.close();
      await bad.destroy();
    }
  });
});
