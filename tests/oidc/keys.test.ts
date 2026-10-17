import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSecretBox } from '../../src/crypto/secrets.js';
import { RETIRED_KEY_GRACE_MS, SigningKeyService } from '../../src/oidc/keys.js';
import { createDb } from '../../src/db/db.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let keys: SigningKeyService;
const box = createSecretBox(Buffer.alloc(32, 5), 'signing-keys');
beforeEach(async () => {
  t = await createTestDb();
  keys = new SigningKeyService(t.db, box);
});
afterEach(() => t.destroy());

describe('SigningKeyService', () => {
  it('creates one RS256 and one ES256 key, idempotently', async () => {
    await keys.ensureKeys();
    await keys.ensureKeys();
    const jwks = await keys.getSigningJwks();
    expect(jwks.map((k) => k.alg).sort()).toEqual(['ES256', 'RS256']);
    for (const k of jwks) {
      expect(k).toMatchObject({ use: 'sig' });
      expect(k.kid).toBeTruthy();
      expect(k.d).toBeTruthy(); // private part present for signing
    }
  });

  it('stores keys encrypted', async () => {
    await keys.ensureKeys();
    const rows = await t.db.selectFrom('signing_keys').select('private_jwk_enc').execute();
    expect(rows).toHaveLength(2);
    for (const r of rows) {
      expect(r.private_jwk_enc).toMatch(/^v1\./);
      expect(() => JSON.parse(r.private_jwk_enc)).toThrow();
      expect(JSON.parse(box.decrypt(r.private_jwk_enc))).toHaveProperty('d');
    }
  });

  it('is safe under concurrent starts from separate connections', async () => {
    const dbs = [createDb(t.url), createDb(t.url), createDb(t.url)];
    try {
      await Promise.all(dbs.map((d) => new SigningKeyService(d, box).ensureKeys()));
      const rows = await t.db.selectFrom('signing_keys').select('alg').where('status', '=', 'active').execute();
      expect(rows.map((r) => r.alg).sort()).toEqual(['ES256', 'RS256']);
    } finally {
      await Promise.all(dbs.map((d) => d.destroy()));
    }
  });

  it('rotates keys, keeping retired keys published during the grace period', async () => {
    await keys.ensureKeys();
    const before = (await keys.getSigningJwks()).map((k) => k.kid);
    await keys.rotate();
    const after = await keys.getSigningJwks();
    expect(after).toHaveLength(4);
    expect(before).not.toContain(after[0]!.kid);
    expect(before).not.toContain(after[1]!.kid);
    expect(after.slice(2).map((k) => k.kid).sort()).toEqual([...before].sort());

    await t.db
      .updateTable('signing_keys')
      .set({ retired_at: new Date(Date.now() - RETIRED_KEY_GRACE_MS - 1000) })
      .where('status', '=', 'retired')
      .execute();
    expect(await keys.getSigningJwks()).toHaveLength(2);
  });
});
