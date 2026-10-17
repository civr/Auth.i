import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { httpUrl, idParams, recordAudit } from './common.js';

const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{1,62}$/, 'use 2-63 lowercase letters, digits or -');
const hostname = z
  .string()
  .max(253)
  .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i, 'must be a bare hostname');
const appFields = {
  name: z.string().min(1).max(200),
  oidcEnabled: z.boolean(),
  forwardAuthEnabled: z.boolean(),
  tokenEndpointAuthMethod: z.enum(['client_secret_basic', 'client_secret_post']),
  redirectUris: z.array(httpUrl).max(20),
  postLogoutRedirectUris: z.array(httpUrl).max(20),
  externalHost: hostname.nullable(),
  allowedGroupIds: z.array(z.uuid()).max(100),
  launchUrl: httpUrl.nullable(),
};
const createBody = z
  .object({ slug, ...appFields })
  .partial()
  .required({ slug: true, name: true })
  .strict();
const updateBody = z.object(appFields).partial().strict();

export function registerApplicationRoutes(api: FastifyInstance, s: Services): void {
  api.get('/applications', async () => ({ items: await s.apps.list() }));

  api.post('/applications', async (req, reply) => {
    const result = await s.apps.create(createBody.parse(req.body));
    await recordAudit(s, req, 'application.create', result.application.id, { slug: result.application.slug });
    return reply.code(201).send(result);
  });

  api.get('/applications/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const app = await s.apps.get(id);
    if (!app) throw new NotFoundError('Application not found');
    return app;
  });

  api.patch('/applications/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const app = await s.apps.update(id, updateBody.parse(req.body));
    await recordAudit(s, req, 'application.update', id);
    return app;
  });

  api.delete('/applications/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.apps.delete(id);
    await recordAudit(s, req, 'application.delete', id);
    return reply.code(204).send();
  });

  api.post('/applications/:id/secret', async (req) => {
    const { id } = idParams.parse(req.params);
    const clientSecret = await s.apps.rotateSecret(id);
    await recordAudit(s, req, 'application.secret_rotate', id);
    return { clientSecret };
  });
}
