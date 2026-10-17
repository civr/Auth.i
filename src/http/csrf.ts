import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { randomToken } from '../crypto/secrets.js';

export const CSRF_COOKIE = 'keystone_csrf';

export function issueCsrfToken(req: FastifyRequest, reply: FastifyReply, config: Config): string {
  const existing = req.cookies[CSRF_COOKIE];
  if (existing && /^[A-Za-z0-9_-]{32}$/.test(existing)) return existing;
  const token = randomToken(24);
  reply.setCookie(CSRF_COOKIE, token, { path: '/', httpOnly: true, sameSite: 'lax', secure: config.secureCookies });
  return token;
}

export function verifyCsrfToken(req: FastifyRequest, submitted: unknown): boolean {
  const expected = req.cookies[CSRF_COOKIE];
  if (!expected || typeof submitted !== 'string' || submitted.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(submitted));
}
