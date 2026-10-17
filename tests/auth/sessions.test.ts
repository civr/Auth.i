import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SessionService } from '../../src/auth/sessions.js';
import { hashToken } from '../../src/crypto/secrets.js';
import { EventBus } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let sessions: SessionService;

beforeEach(async () => {
  t = await createTestDb();
  users = new UserService(t.db, new EventBus());
  sessions = new SessionService(t.db);
});
afterEach(() => t.destroy());

describe('SessionService', () => {
  it('creates and validates sessions; stores only a hash of the token', async () => {
    const u = await users.create({ username: 'alice' });
    const { token, session } = await sessions.create(u.id, { ip: '10.0.0.1', userAgent: 'test' });
    expect(session.userId).toBe(u.id);
    expect((await sessions.validate(token))?.id).toBe(session.id);
    const raw = await t.db.selectFrom('sessions').select('token_hash').executeTakeFirstOrThrow();
    expect(raw.token_hash).toBe(hashToken(token));
    expect(sessions.ttlSeconds).toBe(12 * 60 * 60);
  });

  it('rejects unknown, empty and expired tokens', async () => {
    const u = await users.create({ username: 'alice' });
    expect(await sessions.validate('nope')).toBeNull();
    expect(await sessions.validate(undefined)).toBeNull();
    const shortLived = new SessionService(t.db, 1);
    const { token } = await shortLived.create(u.id);
    await new Promise((r) => setTimeout(r, 10));
    expect(await shortLived.validate(token)).toBeNull();
    expect(await shortLived.purgeExpired()).toBe(1);
  });

  it('rejects sessions of deactivated users', async () => {
    const u = await users.create({ username: 'alice' });
    const { token } = await sessions.create(u.id);
    await users.update(u.id, { isActive: false });
    expect(await sessions.validate(token)).toBeNull();
  });

  it('destroys one or all sessions', async () => {
    const u = await users.create({ username: 'alice' });
    const a = await sessions.create(u.id);
    const b = await sessions.create(u.id);
    await sessions.destroy(a.token);
    expect(await sessions.validate(a.token)).toBeNull();
    expect(await sessions.validate(b.token)).not.toBeNull();
    await sessions.destroyAllForUser(u.id);
    expect(await sessions.validate(b.token)).toBeNull();
  });
});
