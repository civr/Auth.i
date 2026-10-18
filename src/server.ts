import type { FastifyBaseLogger } from 'fastify';
import { ensureBootstrapAdmin } from './bootstrap.js';
import { loadConfig } from './config.js';
import { createDb } from './db/db.js';
import { runMigrations } from './db/migrate.js';
import { buildApp } from './http/app.js';
import { startMaintenance } from './maintenance.js';
import { createServices, startServices } from './services.js';

const config = loadConfig();
const db = createDb(config.databaseUrl);
await runMigrations(db);

// Services exist before the Fastify logger does; route event-handler errors to it once it is available.
let log: FastifyBaseLogger | undefined;
const services = createServices(config, db, {
  logger: {
    error: (obj, msg) => (log ? log.error(obj, msg) : console.error(msg, obj)),
  },
});
await startServices(services);

const app = await buildApp(services, {
  logger: { level: services.settings.current().logLevel },
  onRestart: () => {
    app.log.info('restart requested from admin settings');
    void shutdown()
      .catch((err) => app.log.error({ err }, 'shutdown failed'))
      .finally(() => process.exit(0));
  },
});
log = app.log;

if ((await ensureBootstrapAdmin(services)) === 'created') {
  app.log.info({ username: config.bootstrapAdmin?.username }, 'bootstrap admin created');
}
if (await services.setup.isRequired()) {
  const code = services.setup.issueCode();
  app.log.warn(`Keystone setup code: ${code} — open ${services.settings.current().issuerUrl}/setup`);
}
const stopMaintenance = startMaintenance(services, (err) => app.log.error({ err }, 'maintenance failed'));

let shuttingDown = false;
async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  stopMaintenance();
  await app.close();
  await db.destroy();
}

try {
  await app.listen({ host: '0.0.0.0', port: config.port });
} catch (error) {
  app.log.error({ err: error }, 'server failed to start');
  await shutdown();
  process.exitCode = 1;
}

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    app.log.info({ signal }, 'shutting down');
    try {
      await shutdown();
    } catch (error) {
      app.log.error({ err: error }, 'shutdown failed');
      process.exitCode = 1;
    }
    process.exit();
  });
}
