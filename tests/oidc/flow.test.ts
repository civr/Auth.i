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

  it('signs in through the Keystone login page and issues tokens with profile, email and groups', async () => {
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

  it.each(['ALICE', 'Alice@Example.TEST'])('signs in through the interaction with differently-cased identifier %s', async (identifier) => {
    const config = await discover();
    const browser = new TestBrowser();
    const { verifier, state, page } = await authorize(browser, config);
    expect(page.url.pathname).toBe('/login');
    const done = await browser.signIn(page, identifier, TEST_PASSWORD, isCallback);
    expect(isCallback(done.url)).toBe(true);
    const tokens = await client.authorizationCodeGrant(config, done.url, { pkceCodeVerifier: verifier, expectedState: state });
    expect(tokens.claims()?.sub).toBe(alice.id);
  });

  it('reuses the Keystone session for the next authorization without showing the form', async () => {
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

  it('requires a fresh login after signing out of Keystone', async () => {
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
