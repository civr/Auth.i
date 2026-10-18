import type { FastifyReply, FastifyRequest } from 'fastify';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';
import { currentUser } from './context.js';
import { renderPage } from './views.js';

/** Returns the signed-in admin, or sends a redirect (signed out) / 403 page (not an admin) and returns null. */
export async function requireAdmin(req: FastifyRequest, reply: FastifyReply, s: Services): Promise<User | null> {
  const user = await currentUser(req, s);
  if (!user) {
    const path = req.url.split('?')[0] ?? '/';
    await reply.redirect(`/login?rd=${encodeURIComponent(path)}`);
    return null;
  }
  if (!user.isAdmin) {
    reply.code(403);
    await renderPage(reply, 'error', { title: 'Forbidden', message: 'You need an administrator account to open this page.' });
    return null;
  }
  return user;
}
