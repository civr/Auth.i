import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors.js';
import type { Services } from '../services.js';
import { idParams, recordAudit } from './common.js';

const groupBody = z.object({ name: z.string().min(1).max(100), description: z.string().max(500).optional() }).strict();
const memberParams = z.object({ id: z.uuid(), userId: z.uuid() });

export function registerGroupRoutes(api: FastifyInstance, s: Services): void {
  api.get('/groups', async () => ({ items: await s.groups.list() }));

  api.post('/groups', async (req, reply) => {
    const group = await s.groups.create(groupBody.parse(req.body));
    await recordAudit(s, req, 'group.create', group.id, { name: group.name });
    return reply.code(201).send(group);
  });

  api.get('/groups/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const group = await s.groups.get(id);
    if (!group) throw new NotFoundError('Group not found');
    return { ...group, members: await s.groups.listMembers(id) };
  });

  api.patch('/groups/:id', async (req) => {
    const { id } = idParams.parse(req.params);
    const group = await s.groups.update(id, groupBody.partial().parse(req.body));
    await recordAudit(s, req, 'group.update', id);
    return group;
  });

  api.delete('/groups/:id', async (req, reply) => {
    const { id } = idParams.parse(req.params);
    await s.groups.delete(id);
    await recordAudit(s, req, 'group.delete', id);
    return reply.code(204).send();
  });

  api.put('/groups/:id/members/:userId', async (req, reply) => {
    const { id, userId } = memberParams.parse(req.params);
    await s.groups.addMember(id, userId);
    await recordAudit(s, req, 'group.member_add', id, { userId });
    return reply.code(204).send();
  });

  api.delete('/groups/:id/members/:userId', async (req, reply) => {
    const { id, userId } = memberParams.parse(req.params);
    await s.groups.removeMember(id, userId);
    await recordAudit(s, req, 'group.member_remove', id, { userId });
    return reply.code(204).send();
  });
}
