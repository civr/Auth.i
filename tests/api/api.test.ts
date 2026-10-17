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
    expect((await call('GET', '/users', undefined, 'keystone_wrong')).statusCode).toBe(401);
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
    expect(fetched.json()).not.toHaveProperty('clientSecret');
    expect(fetched.body).not.toContain('client_secret_enc');
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
    expect((await call('POST', '/applications', { ...demo, launchUrl: 'javascript:alert(1)' })).statusCode).toBe(400);
    const nonSlug = await call('POST', '/applications', { ...demo, slug: 'a' });
    expect(nonSlug.statusCode).toBe(400);
    expect(nonSlug.headers['content-type']).toContain('application/problem+json');
    expect(
      (await call('POST', '/applications', { slug: 'p', name: 'P', forwardAuthEnabled: true, externalHost: 'https://x.example.com' }))
        .statusCode,
    ).toBe(400);
  });
});

describe('api tokens and audit API', () => {
  it('rejects malformed audit query params', async () => {
    for (const q of ['before=abc', 'limit=0', 'limit=1000', 'limit=x']) {
      const r = await call('GET', `/audit-log?${q}`);
      expect(r.statusCode).toBe(400);
      expect(r.headers['content-type']).toContain('application/problem+json');
    }
  });

  it('creates, lists and revokes tokens', async () => {
    const created = (await call('POST', '/api-tokens', { name: 'ci' })).json();
    expect(created.token).toMatch(/^keystone_/);
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
