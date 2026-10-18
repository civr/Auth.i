import type { FastifyInstance, FastifyRequest } from 'fastify';
import { canAccess } from '../apps/policy.js';
import { safeRedirectTarget } from '../auth/redirects.js';
import { currentUser, redirectRules } from '../http/context.js';
import type { Services } from '../services.js';

function rawHeader(req: FastifyRequest, name: string): string | undefined {
  const value = req.headers[name];
  const first = Array.isArray(value) ? value[0] : value;
  return first?.trim() || undefined;
}

// Proxies may append to X-Forwarded-Host/-Proto as a comma-separated list; the first entry is the client-facing one.
function listHeader(req: FastifyRequest, name: string): string | undefined {
  return rawHeader(req, name)?.split(',')[0]?.trim() || undefined;
}

// Header values must be printable ASCII; anything else is dropped rather than crashing the response.
function asciiOnly(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : '';
}

export function registerForwardAuthRoutes(app: FastifyInstance, s: Services): void {
  app.get<{ Querystring: { mode?: string } }>('/outpost/auth', async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    // Fail closed on multi-valued hosts: the entry the proxy routed on may not be the one a client supplied.
    const rawHost = req.headers['x-forwarded-host'];
    if (Array.isArray(rawHost) ? rawHost.length > 1 || rawHost[0]?.includes(',') : rawHost?.includes(',')) {
      return reply.code(400).send('Invalid X-Forwarded-Host');
    }
    const host = rawHeader(req, 'x-forwarded-host')?.toLowerCase();
    if (!host) return reply.code(400).send('Missing X-Forwarded-Host');
    const proto = listHeader(req, 'x-forwarded-proto')?.toLowerCase() === 'http' ? 'http' : 'https';
    const uri = rawHeader(req, 'x-forwarded-uri') ?? '/';
    const original = `${proto}://${host}${uri.startsWith('/') ? uri : `/${uri}`}`;

    const application = await s.apps.getByExternalHost(host.replace(/:\d+$/, ''));
    if (!application || !application.forwardAuthEnabled) return reply.code(403).send('Unknown application');

    const loaded = await currentUser(req, s);
    const user = loaded?.isActive ? loaded : null;
    if (!user) {
      if (req.query.mode === 'nginx') return reply.code(401).send('Authentication required');
      const target = safeRedirectTarget(original, await redirectRules(s), '/');
      return reply.redirect(`${s.settings.current().issuerUrl}/login?rd=${encodeURIComponent(target)}`, 302);
    }

    if (!canAccess(user, await s.groups.groupIdsForUser(user.id), application)) {
      await s.audit.record({
        actor: { type: 'user', id: user.id },
        action: 'forward_auth.access_denied',
        target: application.slug,
        ip: req.ip,
      });
      return reply.code(403).send('You do not have access to this application');
    }

    if (asciiOnly(user.username) !== user.username || user.username === '') {
      req.log.error({ userId: user.id }, 'forward-auth: username is not printable ASCII');
      return reply.code(500).send('Internal error');
    }
    const groups = await s.users.groupNames(user.id);
    return reply
      .header('X-Keystone-User', user.username)
      .header('X-Keystone-Email', asciiOnly(user.email ?? ''))
      .header('X-Keystone-Name', encodeURIComponent(user.displayName))
      .header('X-Keystone-Groups', groups.map(encodeURIComponent).join(','))
      .header('X-Keystone-Uid', user.id)
      .code(200)
      .send();
  });
}
