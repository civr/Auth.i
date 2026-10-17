import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createDb, type Db } from '../../src/db/db.js';
import { runMigrations } from '../../src/db/migrate.js';

const ADMIN_URL = process.env.TEST_DATABASE_URL ?? 'postgres://keystone:keystone@localhost:55432/postgres';

export interface TestDb {
  db: Db;
  url: string;
  destroy(): Promise<void>;
}

async function admin(query: string): Promise<void> {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  try {
    await client.query(query);
  } finally {
    await client.end();
  }
}

export async function createTestDb(): Promise<TestDb> {
  const name = `keystone_test_${randomBytes(6).toString('hex')}`;
  await admin(`CREATE DATABASE ${name}`);
  const url = new URL(ADMIN_URL);
  url.pathname = `/${name}`;
  const db = createDb(url.toString());
  await runMigrations(db);
  return {
    db,
    url: url.toString(),
    async destroy() {
      await db.destroy();
      await admin(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    },
  };
}
