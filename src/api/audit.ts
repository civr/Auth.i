import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Services } from '../services.js';

const query = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(100),
  before: z.string().regex(/^\d{1,18}$/, 'must be a numeric id').optional(),
});

export function registerAuditRoutes(api: FastifyInstance, s: Services): void {
  api.get('/audit-log', async (req) => ({ items: await s.audit.list(query.parse(req.query)) }));
}
