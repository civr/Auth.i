import { sql } from 'kysely';
import { passwordSchema, usernameSchema } from './api/common.js';
import type { Services } from './services.js';

// Advisory lock serialising bootstrap across concurrently starting instances
// (distinct from the migrator's 7_424_242 and the signing keys' 7_424_243).
const LOCK_ID = 7_424_244;

export async function ensureBootstrapAdmin(
  s: Pick<Services, 'users' | 'audit' | 'config' | 'db'>,
): Promise<'created' | 'skipped'> {
  const bootstrap = s.config.bootstrapAdmin;
  if (!bootstrap) return 'skipped';
  const username = usernameSchema.safeParse(bootstrap.username);
  if (!username.success) {
    throw new Error(`Invalid KEYSTONE_BOOTSTRAP_ADMIN_USER: ${username.error.issues[0]?.message}`);
  }
  const password = passwordSchema.safeParse(bootstrap.password);
  if (!password.success) {
    throw new Error(`Invalid KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD: ${password.error.issues[0]?.message}`);
  }
  return s.db.transaction().execute(async (trx) => {
    // Held until this transaction ends; a concurrent instance waits here and then sees the committed user.
    await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
    if ((await s.users.count()) > 0) return 'skipped';
    const user = await s.users.create({
      username: username.data,
      email: bootstrap.email ?? null,
      password: password.data,
      isAdmin: true,
    });
    await s.audit.record({ actor: { type: 'system' }, action: 'user.bootstrap', target: user.id });
    return 'created';
  });
}
