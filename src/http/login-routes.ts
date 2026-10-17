import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { canAccess } from '../apps/policy.js';
import { safeRedirectTarget } from '../auth/redirects.js';
import { SESSION_COOKIE } from '../auth/sessions.js';
import type { Services } from '../services.js';
import { currentUser, redirectRules, sessionCookieOptions } from './context.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

type LoginBody = Partial<Record<'csrf' | 'rd' | 'identifier' | 'password', string>>;

export function registerLoginRoutes(app: FastifyInstance, s: Services): void {
  const renderLogin = (
    req: FastifyRequest,
    reply: FastifyReply,
    data: { rd: string; error?: string | null; identifier?: string; loggedOut?: boolean },
  ) =>
    renderPage(reply, 'login', {
      title: 'Sign in',
      csrf: issueCsrfToken(req, reply, s.config),
      rd: data.rd,
      error: data.error ?? null,
      identifier: data.identifier ?? '',
      loggedOut: data.loggedOut ?? false,
    });

  app.get<{ Querystring: { rd?: string; loggedOut?: string } }>('/login', async (req, reply) => {
    const rd = safeRedirectTarget(req.query.rd, await redirectRules(s));
    if (await currentUser(req, s)) return reply.redirect(rd);
    return renderLogin(req, reply, { rd, loggedOut: req.query.loggedOut === '1' });
  });

  app.post<{ Body: LoginBody }>('/login', async (req, reply) => {
    const body = req.body ?? {};
    const rd = safeRedirectTarget(body.rd, await redirectRules(s));
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return renderLogin(req, reply, { rd, error: 'Your sign-in form expired. Please try again.' });
    }
    const identifier = body.identifier ?? '';
    const result = await s.localAuth.authenticate(identifier, body.password ?? '', req.ip);
    if (!result.ok) {
      const limited = result.reason === 'rate_limited';
      reply.code(limited ? 429 : 401);
      return renderLogin(req, reply, {
        rd,
        identifier,
        error: limited ? 'Too many attempts. Try again in a few minutes.' : 'Invalid username or password.',
      });
    }
    const { token } = await s.sessions.create(result.user.id, {
      ip: req.ip,
      ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
    });
    reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions(s.config, s.sessions.ttlSeconds));
    return reply.redirect(rd);
  });

  const logout = async (req: FastifyRequest, reply: FastifyReply) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) {
      const session = await s.sessions.validate(token);
      await s.sessions.destroy(token);
      if (session) await s.audit.record({ actor: { type: 'user', id: session.userId }, action: 'logout', ip: req.ip });
    }
    reply.clearCookie(SESSION_COOKIE, sessionCookieOptions(s.config));
    return reply.redirect('/login?loggedOut=1');
  };
  app.get('/logout', logout);
  app.post('/logout', logout);

  app.get('/', async (req, reply) => {
    const user = await currentUser(req, s);
    if (!user) return reply.redirect('/login');
    const groupIds = await s.groups.groupIdsForUser(user.id);
    const apps = (await s.apps.list()).filter((a) => a.launchUrl && canAccess(user, groupIds, a));
    return renderPage(reply, 'home', { title: 'Your apps', user, apps });
  });
}
