import Fastify from 'fastify';
import { Pool } from 'pg';
import { loadConfig } from './config.js';

const config = loadConfig();
const db = new Pool({ connectionString: config.databaseUrl });
const app = Fastify({
  logger: { level: config.logLevel },
  trustProxy: config.trustProxy.split(',').map((entry) => entry.trim()).filter(Boolean),
});

app.get('/healthz', async (_request, reply) => {
  try {
    await db.query('SELECT 1');
    return { status: 'ok' };
  } catch (error) {
    app.log.error({ err: error }, 'database health check failed');
    return reply.code(503).send({ status: 'unavailable' });
  }
});

try {
  await app.listen({ host: '0.0.0.0', port: config.port });
} catch (error) {
  app.log.error({ err: error }, 'server failed to start');
  await db.end();
  process.exitCode = 1;
}

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    await app.close();
    await db.end();
  });
}