import type { FastifyInstance } from 'fastify';
import type { InteractionResults } from 'oidc-provider';
import { canAccess } from '../apps/policy.js';
import type { Services } from '../services.js';
import { currentUser } from './context.js';

interface PromptDetails {
  missingOIDCClaims?: string[];
  missingResourceScopes?: Record<string, string[]>;
}

export function registerInteractionRoutes(app: FastifyInstance, s: Services): void {
  app.get<{ Params: { uid: string } }>('/interaction/:uid', async (req, reply) => {
    const provider = s.oidc.provider;
    const details = await provider.interactionDetails(req.raw, reply.raw);
    const user = await currentUser(req, s);
    if (!user) {
      return reply.redirect(`/login?rd=${encodeURIComponent(`/interaction/${details.uid}`)}`);
    }

    const clientId = String(details.params.client_id);
    const application = await s.apps.getByClientId(clientId);
    let result: InteractionResults;
    if (!application || !canAccess(user, await s.groups.groupIdsForUser(user.id), application)) {
      await s.audit.record({
        actor: { type: 'user', id: user.id },
        action: 'oidc.access_denied',
        target: clientId,
        ip: req.ip,
      });
      result = { error: 'access_denied', error_description: 'You do not have access to this application' };
    } else {
      const existing = details.grantId ? await provider.Grant.find(details.grantId) : undefined;
      const grant =
        existing && existing.accountId === user.id ? existing : new provider.Grant({ accountId: user.id, clientId });
      grant.addOIDCScope(typeof details.params.scope === 'string' ? details.params.scope : 'openid');
      const missing = details.prompt.details as PromptDetails;
      if (missing.missingOIDCClaims?.length) grant.addOIDCClaims(missing.missingOIDCClaims);
      for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes ?? {})) {
        grant.addResourceScope(indicator, scopes.join(' '));
      }
      result = { login: { accountId: user.id }, consent: { grantId: await grant.save() } };
    }

    reply.hijack();
    try {
      await provider.interactionFinished(req.raw, reply.raw, result, { mergeWithLastSubmission: false });
    } catch (err) {
      req.log.error({ err }, 'interaction finish failed');
      if (!reply.raw.headersSent) {
        reply.raw.statusCode = 500;
        reply.raw.setHeader('content-type', 'text/plain; charset=utf-8');
        reply.raw.end('Internal Server Error');
      } else if (!reply.raw.writableEnded) {
        reply.raw.end();
      }
    }
  });
}
