import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Services } from '../services.js';
import { idParams, recordAudit } from './common.js';

const createBody = z.object({ name: z.string().min(1).max(100), expiresAt: z.iso.datetime().optional() }).strict();

export function registerApiTokenRoutes(api: FastifyInstance, s: Services): void {
  api.get('/api-tokens', async () => ({ items: await s.apiTokens.list() }));

  api.post('/api-tokens', async (req, reply) => {
    const body = createBody.parse(req.body);
    const created = await s.apiTokens.create({
      name: body.name,
      createdBy: req.actor?.type === 'user' ? req.actor.id : null,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
    });
    await recordAudit(s, req, 'api_token.create', created.apiToken.id, { name: body.name });
    return reply.code(201).send(created);
  });

  api.delete('/api-tokens/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.apiTokens.revoke(id);
    await recordAudit(s, req, 'api_token.revoke', id);
    return reply.code(204).send();
  });
}
