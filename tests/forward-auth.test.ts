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
    cookies: opts.session ? { keystone_session: opts.session } : {},
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

  it('keeps commas in X-Forwarded-Uri when building the login redirect', async () => {
    const res = await check({ 'x-forwarded-host': 'wiki.example.test', 'x-forwarded-uri': '/search?tags=a,b' });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.searchParams.get('rd')).toBe('https://wiki.example.test/search?tags=a,b');
  });

  it('uses only the first entry of a comma-separated X-Forwarded-Host/Proto list', async () => {
    const res = await check({ 'x-forwarded-host': 'wiki.example.test, internal.local', 'x-forwarded-proto': 'https, http' });
    expect(res.statusCode).toBe(302);
    expect(new URL(res.headers.location as string).searchParams.get('rd')).toBe('https://wiki.example.test/page?x=1');
  });

  it('answers 401 for anonymous users in nginx mode', async () => {
    expect((await check({ 'x-forwarded-host': 'wiki.example.test' }, { query: '?mode=nginx' })).statusCode).toBe(401);
  });

  it('returns identity headers, encoding non-ASCII names and commas in group names', async () => {
    const res = await check({ 'x-forwarded-host': 'Wiki.Example.test:443' }, { session: sessionToken });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-keystone-user']).toBe('zoe');
    expect(res.headers['x-keystone-email']).toBe('zoe@example.test');
    expect(res.headers['x-keystone-uid']).toBe(zoe.id);
    expect(decodeURIComponent(res.headers['x-keystone-name'] as string)).toBe('Zoë Ångström');
    const groups = (res.headers['x-keystone-groups'] as string).split(',').map(decodeURIComponent);
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

  it('sends an empty email header when the user has no email', async () => {
    await ctx.services.users.update(zoe.id, { email: null });
    const res = await check({ 'x-forwarded-host': 'wiki.example.test' }, { session: sessionToken });
    expect(res.headers['x-keystone-email']).toBe('');
  });
});
