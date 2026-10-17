import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiTokenService } from '../../src/api/tokens.js';
import { hashToken } from '../../src/crypto/secrets.js';
import { NotFoundError } from '../../src/errors.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let tokens: ApiTokenService;
beforeEach(async () => {
  t = await createTestDb();
  tokens = new ApiTokenService(t.db);
});
afterEach(() => t.destroy());

describe('ApiTokenService', () => {
  it('creates prefixed tokens, stores only the hash and verifies them', async () => {
    const { token, apiToken } = await tokens.create({ name: 'ci' });
    expect(token).toMatch(/^keystone_[A-Za-z0-9_-]{43}$/);
    const raw = await t.db.selectFrom('api_tokens').select('token_hash').executeTakeFirstOrThrow();
    expect(raw.token_hash).toBe(hashToken(token));
    const verified = await tokens.verify(token);
    expect(verified?.id).toBe(apiToken.id);
    expect((await tokens.list())[0]?.lastUsedAt).toBeInstanceOf(Date);
  });

  it('rejects unknown and expired tokens', async () => {
    expect(await tokens.verify('keystone_nope')).toBeNull();
    const { token } = await tokens.create({ name: 'old', expiresAt: new Date(Date.now() - 1000) });
    expect(await tokens.verify(token)).toBeNull();
  });

  it('revokes tokens', async () => {
    const { token, apiToken } = await tokens.create({ name: 'ci' });
    await tokens.revoke(apiToken.id);
    expect(await tokens.verify(token)).toBeNull();
    await expect(tokens.revoke(apiToken.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
