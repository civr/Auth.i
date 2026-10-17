import { sql } from 'kysely';
import { afterEach, describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb | undefined;
afterEach(async () => {
  await t?.destroy();
  t = undefined;
});

describe('runMigrations', () => {
  it('creates all core tables', async () => {
    t = await createTestDb(); // runs migrations
    const { rows } = await sql<{ table_name: string }>`
      SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name
    `.execute(t.db);
    expect(rows.map((r) => r.table_name)).toEqual([
      'api_tokens',
      'applications',
      'audit_log',
      'group_members',
      'groups',
      'login_attempts',
      'oidc_payloads',
      'schema_migrations',
      'sessions',
      'signing_keys',
      'users',
    ]);
  });

  it('is a no-op the second time', async () => {
    t = await createTestDb();
    expect(await runMigrations(t.db)).toEqual([]);
  });

  it('applies each migration once under concurrent runs', async () => {
    t = await createTestDb();
    await sql`DELETE FROM schema_migrations`.execute(t.db);
    await sql`DROP TABLE users, groups, group_members, applications, sessions, oidc_payloads, signing_keys, api_tokens, audit_log, login_attempts CASCADE`.execute(t.db);
    const results = await Promise.all([runMigrations(t.db), runMigrations(t.db), runMigrations(t.db)]);
    expect(results.flat()).toEqual(['001_core.sql']);
  });
});
