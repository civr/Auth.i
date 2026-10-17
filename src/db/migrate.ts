import { readdir, readFile } from 'node:fs/promises';
import { sql } from 'kysely';
import type { Db } from './db.js';

// Resolves to <project>/migrations from both src/db (tsx) and dist/db (compiled).
const MIGRATIONS_DIR = new URL('../../migrations/', import.meta.url);
const LOCK_ID = 7_424_242; // arbitrary, unique to Keystone

export async function runMigrations(db: Db): Promise<string[]> {
  return db.connection().execute(async (conn) => {
    await sql`SELECT pg_advisory_lock(${LOCK_ID})`.execute(conn);
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          name text PRIMARY KEY,
          applied_at timestamptz NOT NULL DEFAULT now()
        )
      `.execute(conn);
      const applied = new Set(
        (await conn.selectFrom('schema_migrations').select('name').execute()).map((r) => r.name),
      );
      const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort();
      const ran: string[] = [];
      for (const file of files) {
        if (applied.has(file)) continue;
        const text = await readFile(new URL(file, MIGRATIONS_DIR), 'utf8');
        await conn.transaction().execute(async (trx) => {
          await sql.raw(text).execute(trx);
          await trx.insertInto('schema_migrations').values({ name: file }).execute();
        });
        ran.push(file);
      }
      return ran;
    } finally {
      await sql`SELECT pg_advisory_unlock(${LOCK_ID})`.execute(conn);
    }
  });
}
