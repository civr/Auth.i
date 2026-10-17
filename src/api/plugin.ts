import type { FastifyInstance } from 'fastify';
import { UnauthorizedError } from '../errors.js';
import type { Services } from '../services.js';
import { registerApiTokenRoutes } from './api-tokens.js';
import { registerApplicationRoutes } from './applications.js';
import { registerAuditRoutes } from './audit.js';
import './common.js';
import { registerGroupRoutes } from './groups.js';
import { registerKeyRoutes } from './keys.js';
import { registerUserRoutes } from './users.js';

export async function registerApi(app: FastifyInstance, s: Services): Promise<void> {
  await app.register(
    async (api) => {
      api.decorateRequest('actor', null);
      api.addHook('onRequest', async (req) => {
        const match = req.headers.authorization?.match(/^Bearer\s+(\S+)$/i);
        const token = match?.[1] ? await s.apiTokens.verify(match[1]) : null;
        if (!token) throw new UnauthorizedError();
        req.actor = { type: 'token', id: token.id };
      });
      registerUserRoutes(api, s);
      registerGroupRoutes(api, s);
      registerApplicationRoutes(api, s);
      registerApiTokenRoutes(api, s);
      registerAuditRoutes(api, s);
      registerKeyRoutes(api, s);
    },
    { prefix: '/api/v1' },
  );
}
