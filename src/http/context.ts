import type { CookieSerializeOptions } from '@fastify/cookie';
import type { FastifyRequest } from 'fastify';
import type { RedirectRules } from '../auth/redirects.js';
import { SESSION_COOKIE } from '../auth/sessions.js';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';
import type { EffectiveSettings } from '../settings/settings.js';

export async function currentUser(req: FastifyRequest, s: Pick<Services, 'sessions' | 'users'>): Promise<User | null> {
  const session = await s.sessions.validate(req.cookies[SESSION_COOKIE]);
  return session ? s.users.get(session.userId) : null;
}

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
