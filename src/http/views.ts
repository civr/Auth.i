import { fileURLToPath } from 'node:url';
import { Eta } from 'eta';
import type { FastifyReply } from 'fastify';

const eta = new Eta({
  views: fileURLToPath(new URL('../../views/', import.meta.url)),
  cache: process.env.NODE_ENV === 'production',
});

export function renderPage(reply: FastifyReply, template: string, data: Record<string, unknown>): FastifyReply {
  return reply.type('text/html; charset=utf-8').send(eta.render(template, data));
}
