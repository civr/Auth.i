import type { CookieSerializeOptions } from '@fastify/cookie';
import type { FastifyRequest } from 'fastify';
import type { RedirectRules } from '../auth/redirects.js';
import { SESSION_COOKIE } from '../auth/sessions.js';
import type { Config } from '../config.js';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';

export async function currentUser(req: FastifyRequest, s: Pick<Services, 'sessions' | 'users'>): Promise<User | null> {
  const session = await s.sessions.validate(req.cookies[SESSION_COOKIE]);
  return session ? s.users.get(session.userId) : null;
}

export function sessionCookieOptions(config: Config, maxAgeSeconds?: number): CookieSerializeOptions {
  return {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    ...(config.cookieDomain ? { domain: config.cookieDomain } : {}),
    ...(maxAgeSeconds !== undefined ? { maxAge: maxAgeSeconds } : {}),
  };
}

export async function redirectRules(s: Pick<Services, 'config' | 'apps'>): Promise<RedirectRules> {
  return {
    issuerUrl: s.config.issuerUrl,
    ...(s.config.cookieDomain ? { cookieDomain: s.config.cookieDomain } : {}),
    allowedHosts: await s.apps.forwardAuthHosts(),
  };
}
