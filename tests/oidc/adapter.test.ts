import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PostgresAdapter, purgeExpiredOidcPayloads } from '../../src/oidc/adapter.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
const noClient = async () => undefined;
beforeEach(async () => {
  t = await createTestDb();
});
afterEach(() => t.destroy());

describe('PostgresAdapter', () => {
  it('upserts and finds payloads by id, uid and user code', async () => {
    const a = new PostgresAdapter('Interaction', t.db, noClient);
    await a.upsert('i1', { uid: 'u1', userCode: 'UC1', returnTo: '/x' }, 60);
    expect(await a.find('i1')).toMatchObject({ uid: 'u1', returnTo: '/x' });
    expect(await a.findByUid('u1')).toMatchObject({ returnTo: '/x' });
    expect(await a.findByUserCode('UC1')).toMatchObject({ returnTo: '/x' });
    await a.upsert('i1', { uid: 'u1', returnTo: '/y' }, 60);
    expect(await a.find('i1')).toMatchObject({ returnTo: '/y' });
  });

  it('separates models by name', async () => {
    await new PostgresAdapter('Session', t.db, noClient).upsert('same', { kind: 'Session' }, 60);
    expect(await new PostgresAdapter('Grant', t.db, noClient).find('same')).toBeUndefined();
  });

  it('hides expired payloads and purges them', async () => {
    const a = new PostgresAdapter('AccessToken', t.db, noClient);
    await a.upsert('old', { grantId: 'g' }, -1);
    expect(await a.find('old')).toBeUndefined();
    expect(await purgeExpiredOidcPayloads(t.db)).toBe(1);
  });

  it('marks payloads consumed', async () => {
    const a = new PostgresAdapter('AuthorizationCode', t.db, noClient);
    await a.upsert('c1', { grantId: 'g' }, 60);
    await a.consume('c1');
    expect(await a.find('c1')).toMatchObject({ consumed: true });
  });

  it('destroys and revokes by grant across models', async () => {
    const codes = new PostgresAdapter('AuthorizationCode', t.db, noClient);
    const refresh = new PostgresAdapter('RefreshToken', t.db, noClient);
    await codes.upsert('c1', { grantId: 'g1' }, 60);
    await refresh.upsert('r1', { grantId: 'g1' }, 60);
    await refresh.upsert('r2', { grantId: 'g2' }, 60);
    await codes.revokeByGrantId('g1');
    expect(await codes.find('c1')).toBeUndefined();
    expect(await refresh.find('r1')).toBeUndefined();
    expect(await refresh.find('r2')).toBeDefined();
    await refresh.destroy('r2');
    expect(await refresh.find('r2')).toBeUndefined();
  });

  it('loads clients through the client loader', async () => {
    const a = new PostgresAdapter('Client', t.db, async (id) => (id === 'demo' ? { client_id: 'demo' } : undefined));
    expect(await a.find('demo')).toEqual({ client_id: 'demo' });
    expect(await a.find('other')).toBeUndefined();
  });
});
