import type { FastifyInstance } from 'fastify';
import type { Services } from '../services.js';
import { recordAudit } from './common.js';

export function registerKeyRoutes(api: FastifyInstance, s: Services): void {
  api.post('/keys/rotate', async (req, reply) => {
    await s.keys.rotate();
    await s.oidc.load();
    await recordAudit(s, req, 'keys.rotate');
    return reply.code(204).send();
  });
}
