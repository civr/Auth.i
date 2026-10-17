import { sql } from 'kysely';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import type { SecretBox } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';

export type SigningJwk = JsonWebKey & { kid: string; alg: 'RS256' | 'ES256'; use: 'sig' };

const ALGS = ['RS256', 'ES256'] as const;
const LOCK_ID = 7_424_243; // advisory lock serialising key creation (distinct from migrator's)
export const RETIRED_KEY_GRACE_MS = 24 * 60 * 60 * 1000;

function generateJwk(alg: (typeof ALGS)[number]): SigningJwk {
  const { privateKey } =
    alg === 'RS256'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), alg, use: 'sig' };
}

export class SigningKeyService {
  constructor(
    private readonly db: Db,
    private readonly box: SecretBox,
  ) {}

  async ensureKeys(): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
      const active = await trx.selectFrom('signing_keys').select('alg').where('status', '=', 'active').execute();
      const have = new Set(active.map((r) => r.alg));
      for (const alg of ALGS) {
        if (!have.has(alg)) await this.insert(trx, alg);
      }
    });
  }

  async rotate(): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
      await trx
        .updateTable('signing_keys')
        .set({ status: 'retired', retired_at: new Date() })
        .where('status', '=', 'active')
        .execute();
      for (const alg of ALGS) await this.insert(trx, alg);
    });
  }

  async getSigningJwks(): Promise<SigningJwk[]> {
    const rows = await this.db
      .selectFrom('signing_keys')
      .select('private_jwk_enc')
      .where((eb) =>
        eb.or([
          eb('status', '=', 'active'),
          eb('retired_at', '>', new Date(Date.now() - RETIRED_KEY_GRACE_MS)),
        ]),
      )
      .orderBy('status', 'asc') // 'active' sorts before 'retired'
      .orderBy('created_at', 'desc')
      .execute();
    return rows.map((r) => JSON.parse(this.box.decrypt(r.private_jwk_enc)) as SigningJwk);
  }

  private async insert(db: Db, alg: (typeof ALGS)[number]): Promise<void> {
    const jwk = generateJwk(alg);
    await db
      .insertInto('signing_keys')
      .values({ kid: jwk.kid, alg, private_jwk_enc: this.box.encrypt(JSON.stringify(jwk)), status: 'active', retired_at: null })
      .execute();
  }
}
