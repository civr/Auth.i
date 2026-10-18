import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { SESSION_COOKIE } from '../auth/sessions.js';
import { applySettingsChange, type Services } from '../services.js';
import { sessionCookieOptions } from './context.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

const FIELDS = ['code', 'issuerUrl', 'username', 'email', 'password', 'passwordConfirm'] as const;
type SetupBody = Partial<Record<(typeof FIELDS)[number] | 'csrf', unknown>>;

/** req.protocol and req.host honour trustProxy (Fastify 5). */
function detectedIssuer(req: FastifyRequest): string {
  return `${req.protocol}://${req.host || 'localhost:9000'}`;
}

/** While no user exists, pages go to /setup and machine endpoints answer 503. Register before middie. */
export function registerSetupGate(app: FastifyInstance, s: Services): void {
  app.addHook('onRequest', async (req, reply) => {
    const path = req.url.split('?')[0] ?? '/';
    if (path === '/setup' || path === '/healthz') return;
    if (!(await s.setup.isRequired())) return;
    if (path.startsWith('/api/') || path.startsWith('/oidc') || path.startsWith('/outpost/')) {
      return reply
        .code(503)
        .type('application/problem+json')
        .send({ type: 'about:blank', title: 'Setup required', status: 503, detail: 'Finish setup at /setup first.' });
    }
    return reply.redirect('/setup');
  });
}

export function registerSetupRoutes(app: FastifyInstance, s: Services): void {
  const render = (
    req: FastifyRequest,
    reply: FastifyReply,
    data: { values: Record<string, string>; errors?: Record<string, string>; error?: string | null },
  ) =>
    renderPage(reply, 'setup', {
      title: 'Set up Keystone',
      csrf: issueCsrfToken(req, reply, s.settings.current()),
      values: data.values,
      errors: data.errors ?? {},
      error: data.error ?? null,
      issuerLocked: s.settings.isLocked('issuerUrl'),
    });

  app.get('/setup', async (req, reply) => {
    if (!(await s.setup.isRequired())) return reply.callNotFound();
    const issuerUrl = s.settings.isLocked('issuerUrl') ? s.settings.current().issuerUrl : detectedIssuer(req);
    return render(req, reply, { values: { issuerUrl, username: 'admin', email: '' } });
  });

  app.post<{ Body: SetupBody }>('/setup', async (req, reply) => {
    if (!(await s.setup.isRequired())) return reply.callNotFound();
    const body = req.body ?? {};
    const str = (k: (typeof FIELDS)[number]) => (typeof body[k] === 'string' ? (body[k] as string) : '');
    const values = { issuerUrl: str('issuerUrl'), username: str('username'), email: str('email') };
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return render(req, reply, { values, error: 'The form expired. Please try again.' });
    }
    const result = await s.setup.complete(
      {
        code: str('code'),
        issuerUrl: s.settings.isLocked('issuerUrl') ? s.settings.current().issuerUrl : values.issuerUrl,
        username: values.username,
        email: values.email,
        password: str('password'),
        passwordConfirm: str('passwordConfirm'),
      },
      req.ip,
    );
    if (!result.ok) {
      if (result.reason === 'already_complete') return reply.callNotFound();
      if (result.reason === 'rate_limited') {
        reply.code(429);
        return render(req, reply, { values, error: 'Too many attempts. Try again in 15 minutes.' });
      }
      reply.code(400);
      if (result.reason === 'invalid') return render(req, reply, { values, errors: result.fieldErrors });
      return render(req, reply, { values, error: 'Setup code is incorrect.' });
    }
    await applySettingsChange(s, result.changed);
    const { token } = await s.sessions.create(result.user.id, {
      ip: req.ip,
      ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
    });
    reply.setCookie(SESSION_COOKIE, token, sessionCookieOptions(s.settings.current(), s.sessions.ttlSeconds));
    return reply.redirect('/admin/settings');
  });
}
