import type { Selectable } from 'kysely';
import { hashToken, randomToken } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import type { ApiTokensTable } from '../db/schema.js';
import { NotFoundError } from '../errors.js';
import { isUuid } from '../util.js';

export interface ApiToken {
  id: string;
  name: string;
  createdBy: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
}

function toApiToken(row: Selectable<ApiTokensTable>): ApiToken {
  return {
    id: row.id,
    name: row.name,
    createdBy: row.created_by,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
  };
}

export class ApiTokenService {
  constructor(private readonly db: Db) {}

  async create(input: { name: string; createdBy?: string | null; expiresAt?: Date | null }): Promise<{ token: string; apiToken: ApiToken }> {
    const token = `keystone_${randomToken(32)}`;
    const row = await this.db
      .insertInto('api_tokens')
      .values({
        name: input.name,
        token_hash: hashToken(token),
        created_by: input.createdBy ?? null,
        expires_at: input.expiresAt ?? null,
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    return { token, apiToken: toApiToken(row) };
  }

  async verify(token: string): Promise<ApiToken | null> {
    const row = await this.db
      .updateTable('api_tokens')
      .set({ last_used_at: new Date() })
      .where('token_hash', '=', hashToken(token))
      .where((eb) => eb.or([eb('expires_at', 'is', null), eb('expires_at', '>', new Date())]))
      .returningAll()
      .executeTakeFirst();
    return row ? toApiToken(row) : null;
  }

  async list(): Promise<ApiToken[]> {
    return (await this.db.selectFrom('api_tokens').selectAll().orderBy('created_at').execute()).map(toApiToken);
  }

  async revoke(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('api_tokens').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('API token not found');
  }
}
