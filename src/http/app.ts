import { STATUS_CODES, type IncomingMessage, type ServerResponse } from 'node:http';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import middie from '@fastify/middie';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { sql } from 'kysely';
import { errors as oidcErrors } from 'oidc-provider';
import { ZodError } from 'zod';
import { registerApi } from '../api/plugin.js';
import { AppError } from '../errors.js';
import type { Services } from '../services.js';
import { registerForwardAuthRoutes } from '../forward-auth/routes.js';
import { registerAdminRoutes } from './admin-routes.js';
import { registerInteractionRoutes } from './interaction-routes.js';
import { registerLoginRoutes } from './login-routes.js';
import { registerSetupGate, registerSetupRoutes } from './setup-routes.js';
import { renderPage } from './views.js';

export interface BuildAppOptions {
  logger?: boolean | { level: string };
  setupGate?: boolean;
  onRestart?: () => void;
}

interface DescribedError {
  status: number;
  title: string;
  detail: string;
  extra?: Record<string, unknown>;
}

function describeError(err: unknown): DescribedError {
  if (err instanceof oidcErrors.SessionNotFound) {
    return {
      status: 400,
      title: 'Sign-in expired',
      detail: 'Your sign-in request expired. Go back to the application and try again.',
    };
  }
  if (err instanceof ZodError) {
    return {
      status: 400,
      title: 'Bad Request',
      detail: 'Validation failed',
      extra: { errors: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
    };
  }
  if (err instanceof AppError) return { status: err.status, title: err.title, detail: err.message };
  const statusCode = (err as FastifyError).statusCode;
  if (statusCode && statusCode >= 400 && statusCode < 500) {
    return { status: statusCode, title: STATUS_CODES[statusCode] ?? 'Error', detail: (err as Error).message };
  }
  return { status: 500, title: 'Internal Server Error', detail: 'An unexpected error occurred' };
}

function sendError(req: FastifyRequest, reply: FastifyReply, e: DescribedError): FastifyReply {
  reply.code(e.status);
  if (req.url.startsWith('/api/')) {
    return reply
      .type('application/problem+json')
      .send({ type: 'about:blank', title: e.title, status: e.status, detail: e.detail, ...e.extra });
  }
  return renderPage(reply, 'error', {
    title: e.title,
    message: e.status >= 500 ? 'Something went wrong. Please try again.' : e.detail,
  });
}

/** 'true'/'false' become booleans; anything else is a comma-separated list of addresses or presets. */
export function parseTrustProxy(value: string): boolean | string[] {
  const v = value.trim().toLowerCase();
  if (v === 'true') return true;
  if (v === 'false') return false;
  return value.split(',').map((e) => e.trim()).filter(Boolean);
}

export async function buildApp(s: Services, opts: BuildAppOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: opts.logger ?? false,
    trustProxy: parseTrustProxy(s.settings.current().trustProxy),
  });
  await app.register(cookie);
  await app.register(formbody);
  if (opts.setupGate ?? true) registerSetupGate(app, s);
  await app.register(middie);
  // oidc-provider is a Koa app; middie hands it the raw request before Fastify parses the body.
  app.use('/oidc', (req: IncomingMessage, res: ServerResponse) => s.oidc.handle(req, res));

  app.addHook('onSend', async (_req, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'same-origin');
    reply.header(
      'Content-Security-Policy',
      "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
    );
    if (s.settings.current().secureCookies) reply.header('Strict-Transport-Security', 'max-age=31536000');
    return payload;
  });

  app.setErrorHandler((err, req, reply) => {
    const described = describeError(err);
    if (described.status >= 500) req.log.error({ err }, 'request failed');
    return sendError(req, reply, described);
  });

  app.setNotFoundHandler((req, reply) =>
    sendError(req, reply, { status: 404, title: 'Not Found', detail: 'This page does not exist.' }),
  );

  app.get('/healthz', async (req, reply) => {
    try {
      await sql`SELECT 1`.execute(s.db);
      return { status: 'ok' };
    } catch (err) {
      req.log.error({ err }, 'database health check failed');
      return reply.code(503).send({ status: 'unavailable' });
    }
  });

  registerLoginRoutes(app, s);
  registerSetupRoutes(app, s);
  registerAdminRoutes(app, s, { ...(opts.onRestart ? { onRestart: opts.onRestart } : {}) });
  registerInteractionRoutes(app, s);
  registerForwardAuthRoutes(app, s);
  await registerApi(app, s);
  return app;
}
