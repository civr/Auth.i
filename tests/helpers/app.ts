import type { FastifyInstance } from 'fastify';
import type { Config } from '../../src/config.js';
import { buildApp } from '../../src/http/app.js';
import { createServices, type Services } from '../../src/services.js';
import { createTestDb } from './db.js';

export const TEST_PASSWORD = 'correct-horse-battery';

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    issuerUrl: 'http://127.0.0.1:9000',
    cookieDomain: undefined,
    secureCookies: false,
    secretKey: Buffer.alloc(32, 1),
    databaseUrl: '',
    bootstrapAdmin: undefined,
    trustProxy: 'loopback',
    port: 9000,
    logLevel: 'silent',
    ...overrides,
  };
}

export interface TestContext {
  services: Services;
  app: FastifyInstance;
  close(): Promise<void>;
}

export async function createTestContext(overrides: Partial<Config> = {}): Promise<TestContext> {
  const tdb = await createTestDb();
  const services = createServices(testConfig({ databaseUrl: tdb.url, ...overrides }), tdb.db);
  const app = await buildApp(services);
  return {
    services,
    app,
    async close() {
      await app.close();
      await tdb.destroy();
    },
  };
}
