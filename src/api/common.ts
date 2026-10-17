import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Actor } from '../audit/audit.js';
import type { Services } from '../services.js';

declare module 'fastify' {
  interface FastifyRequest {
    actor: Actor | null;
  }
}

export const idParams = z.object({ id: z.uuid() });
export const usernameSchema = z
  .string()
  .regex(/^[a-zA-Z0-9._@-]{2,64}$/, 'use 2-64 letters, digits or . _ @ -');
export const passwordSchema = z.string().min(12, 'must be at least 12 characters').max(256);
export const httpUrl = z
  .url({ protocol: /^https?$/ })
  .refine((u) => !/[\s\u0000-\u001f\u007f]/.test(u), 'must not contain whitespace or control characters');

export async function recordAudit(
  s: Services,
  req: FastifyRequest,
  action: string,
  target: string | null = null,
  details: Record<string, unknown> = {},
): Promise<void> {
  await s.audit.record({ actor: req.actor ?? { type: 'anonymous' }, action, target, details, ip: req.ip });
}
