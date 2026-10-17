import { hashToken, randomToken } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import { isUuid } from '../util.js';

export const SESSION_COOKIE = 'keystone_session';

export interface Session {
  id: string;
  userId: string;
  expiresAt: Date;
}

const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

export class SessionService {
  constructor(
    private readonly db: Db,
    private readonly ttlMs: number = DEFAULT_TTL_MS,
  ) {}

  get ttlSeconds(): number {
    return Math.floor(this.ttlMs / 1000);
  }

  async create(userId: string, meta: { ip?: string; userAgent?: string } = {}): Promise<{ token: string; session: Session }> {
    const token = randomToken();
    const row = await this.db
      .insertInto('sessions')
      .values({
        token_hash: hashToken(token),
        user_id: userId,
        expires_at: new Date(Date.now() + this.ttlMs),
        ip: meta.ip ?? null,
        user_agent: meta.userAgent?.slice(0, 512) ?? null,
      })
      .returning(['id', 'user_id', 'expires_at'])
      .executeTakeFirstOrThrow();
    return { token, session: { id: row.id, userId: row.user_id, expiresAt: row.expires_at } };
  }

  async validate(token: string | undefined | null): Promise<Session | null> {
    if (!token) return null;
    const row = await this.db
      .selectFrom('sessions')
      .innerJoin('users', 'users.id', 'sessions.user_id')
      .select(['sessions.id', 'sessions.user_id', 'sessions.expires_at'])
      .where('sessions.token_hash', '=', hashToken(token))
      .where('sessions.expires_at', '>', new Date())
      .where('users.is_active', '=', true)
      .executeTakeFirst();
    if (!row) return null;
    await this.db.updateTable('sessions').set({ last_seen_at: new Date() }).where('id', '=', row.id).execute();
    return { id: row.id, userId: row.user_id, expiresAt: row.expires_at };
  }

  async destroy(token: string): Promise<void> {
    await this.db.deleteFrom('sessions').where('token_hash', '=', hashToken(token)).execute();
  }

  async destroyAllForUser(userId: string): Promise<void> {
    if (!isUuid(userId)) return;
    await this.db.deleteFrom('sessions').where('user_id', '=', userId).execute();
  }

  async purgeExpired(): Promise<number> {
    const result = await this.db.deleteFrom('sessions').where('expires_at', '<=', new Date()).executeTakeFirst();
    return Number(result.numDeletedRows);
  }
}
