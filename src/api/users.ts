import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { idParams, passwordSchema, recordAudit, usernameSchema } from './common.js';

const createUserBody = z
  .object({
    username: usernameSchema,
    email: z.email().nullable().optional(),
    displayName: z.string().min(1).max(200).optional(),
    givenName: z.string().max(100).nullable().optional(),
    familyName: z.string().max(100).nullable().optional(),
    isAdmin: z.boolean().optional(),
    isActive: z.boolean().optional(),
    password: passwordSchema.optional(),
  })
  .strict();
const updateUserBody = createUserBody.omit({ password: true }).partial().strict();
const listQuery = z.object({
  search: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export function registerUserRoutes(api: FastifyInstance, s: Services): void {
  api.get('/users', async (req) => ({ items: await s.users.list(listQuery.parse(req.query)) }));

  api.post('/users', async (req, reply) => {
    const user = await s.users.create(createUserBody.parse(req.body));
    await recordAudit(s, req, 'user.create', user.id, { username: user.username });
    return reply.code(201).send(user);
  });

  api.get('/users/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const user = await s.users.get(id);
    if (!user) throw new NotFoundError('User not found');
    return { ...user, groups: await s.groups.groupsForUser(id) };
  });

  api.patch('/users/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const body = updateUserBody.parse(req.body);
    const user = await s.users.update(id, body);
    if (body.isActive === false) await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.update', id, { fields: Object.keys(body) });
    return user;
  });

  api.delete('/users/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.users.delete(id);
    await recordAudit(s, req, 'user.delete', id);
    return reply.code(204).send();
  });

  api.put('/users/:id/password', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    const { password } = z.object({ password: passwordSchema }).strict().parse(req.body);
    await s.users.setPassword(id, password);
    await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.password_set', id);
    return reply.code(204).send();
  });

  api.delete('/users/:id/sessions', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    if (!(await s.users.get(id))) throw new NotFoundError('User not found');
    await s.sessions.destroyAllForUser(id);
    await recordAudit(s, req, 'user.sessions_revoked', id);
    return reply.code(204).send();
  });
}
