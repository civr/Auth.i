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
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} · Keystone</title></head><body style="font:16px/1.5 system-ui,sans-serif;max-width:420px;margin:15vh auto;padding:0 16px">${body}</body></html>`;
}

export async function createOidcProvider(d: OidcDeps): Promise<Provider> {
  const policy = interactionPolicy.base();
  policy.get('login')!.checks.add(
    new interactionPolicy.Check(
      'keystone_session',
      'Keystone session is missing, belongs to another user, or the account may no longer use this client',
      'login_required',
      async (ctx: KoaContextWithOIDC) => {
        const token = ctx.cookies.get(SESSION_COOKIE, { signed: false });
        const session = await d.sessions.validate(token);
        // ctx.oidc.account is undefined when findAccount rejects the user (inactive or lost access); prompting
        // routes them through the interaction, which returns an audited access_denied instead of a server_error.
        return session && ctx.oidc.account && session.userId === ctx.oidc.session?.accountId
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
    jwks: { keys: (await d.keys.getSigningJwks()) as unknown as NonNullable<Configuration['jwks']>['keys'] },
    cookies: { keys: [deriveKey(d.config.secretKey, 'oidc-cookies').toString('base64url')] },
    findAccount,
    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name', 'preferred_username'],
      email: ['email', 'email_verified'],
      groups: ['groups'],
    },
    scopes: ['openid', 'offline_access', 'profile', 'email', 'groups'],
    responseTypes: ['code'],
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
  // Koa's proxy = true trusts X-Forwarded-* from ANY peer (Fastify's trustProxy does not apply here). Acceptable
  // because Keystone is only reachable through the TLS-terminating reverse proxy (port bound to loopback).
  provider.proxy = true;
  provider.on('end_session.success', (ctx: KoaContextWithOIDC) => {
    const token = ctx.cookies.get(SESSION_COOKIE, { signed: false });
    if (token) void d.sessions.destroy(token).catch(() => {});
  });
  return provider;
}
