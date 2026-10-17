import type { Adapter, AdapterPayload } from 'oidc-provider';
import type { Db } from '../db/db.js';

export class PostgresAdapter implements Adapter {
  constructor(
    private readonly name: string,
    private readonly db: Db,
    private readonly loadClient: (clientId: string) => Promise<AdapterPayload | undefined>,
  ) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    const values = {
      payload: JSON.stringify(payload),
      grant_id: typeof payload.grantId === 'string' ? payload.grantId : null,
      user_code: typeof payload.userCode === 'string' ? payload.userCode : null,
      uid: typeof payload.uid === 'string' ? payload.uid : null,
      expires_at: expiresIn === undefined ? null : new Date(Date.now() + expiresIn * 1000),
    };
    await this.db
      .insertInto('oidc_payloads')
      .values({ id, type: this.name, consumed_at: null, ...values })
      .onConflict((oc) => oc.columns(['type', 'id']).doUpdateSet(values))
      .execute();
  }

  find(id: string): Promise<AdapterPayload | undefined> {
    if (this.name === 'Client') return this.loadClient(id);
    return this.findBy('id', id);
  }

  findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.findBy('uid', uid);
  }

  findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.findBy('user_code', userCode);
  }

  async consume(id: string): Promise<void> {
    await this.db
      .updateTable('oidc_payloads')
      .set({ consumed_at: new Date() })
      .where('type', '=', this.name)
      .where('id', '=', id)
      .execute();
  }

  async destroy(id: string): Promise<void> {
    await this.db.deleteFrom('oidc_payloads').where('type', '=', this.name).where('id', '=', id).execute();
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.db.deleteFrom('oidc_payloads').where('grant_id', '=', grantId).execute();
  }

  private async findBy(column: 'id' | 'uid' | 'user_code', value: string): Promise<AdapterPayload | undefined> {
    const row = await this.db
      .selectFrom('oidc_payloads')
      .select(['payload', 'consumed_at', 'expires_at'])
      .where('type', '=', this.name)
      .where(column, '=', value)
      .executeTakeFirst();
    if (!row || (row.expires_at && row.expires_at <= new Date())) return undefined;
    return { ...(row.payload as AdapterPayload), ...(row.consumed_at ? { consumed: true } : {}) };
  }
}

export async function purgeExpiredOidcPayloads(db: Db): Promise<number> {
  const result = await db.deleteFrom('oidc_payloads').where('expires_at', '<=', new Date()).executeTakeFirst();
  return Number(result.numDeletedRows);
}
