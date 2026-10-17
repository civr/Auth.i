import type { FastifyInstance } from 'fastify';
import type { Config } from '../../src/config.js';
import { buildApp } from '../../src/http/app.js';
import { createServices, startServices, type Services } from '../../src/services.js';
import { createTestDb } from './db.js';
import { getFreePort } from './net.js';

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
  await startServices(services);
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

export interface ListeningContext extends TestContext {
  baseUrl: string;
}

export async function createListeningContext(): Promise<ListeningContext> {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const ctx = await createTestContext({ issuerUrl: baseUrl, port });
  await ctx.app.listen({ port, host: '127.0.0.1' });
  return { ...ctx, baseUrl };
}
