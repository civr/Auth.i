import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit/audit.js';
import { LocalAuthenticator } from '../../src/auth/local-login.js';
import { LoginRateLimiter } from '../../src/auth/rate-limit.js';
import { EventBus } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

const PASSWORD = 'correct-horse-battery';
let t: TestDb;
let users: UserService;
let audit: AuditLog;
let auth: LocalAuthenticator;

beforeEach(async () => {
  t = await createTestDb();
  users = new UserService(t.db, new EventBus());
  audit = new AuditLog(t.db);
  auth = new LocalAuthenticator(users, new LoginRateLimiter(t.db, { maxPerUser: 3, maxPerIp: 5 }), audit);
  await users.create({ username: 'alice', email: 'alice@example.com', password: PASSWORD });
});
afterEach(() => t.destroy());

describe('LocalAuthenticator', () => {
  it('accepts username or email in any case', async () => {
    for (const id of ['alice', 'ALICE', 'Alice@Example.com', '  alice  ']) {
      const r = await auth.authenticate(id, PASSWORD, '10.0.0.1');
      expect(r.ok).toBe(true);
    }
    const actions = (await audit.list()).map((e) => e.action);
    expect(actions.every((a) => a === 'login.success')).toBe(true);
  });

  it('rejects a wrong password and unknown users alike', async () => {
    expect(await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1')).toEqual({
      ok: false,
      reason: 'invalid_credentials',
    });
    expect(await auth.authenticate('mallory', PASSWORD, '10.0.0.1')).toEqual({
      ok: false,
      reason: 'invalid_credentials',
    });
    expect((await audit.list()).map((e) => e.action)).toEqual(['login.failed', 'login.failed']);
  });

  it('rejects inactive users', async () => {
    const found = await users.findByLogin('alice');
    await users.update(found!.user.id, { isActive: false });
    expect(await auth.authenticate('alice', PASSWORD, '10.0.0.1')).toEqual({ ok: false, reason: 'inactive' });
  });

  it('rate-limits per user regardless of identifier case, even with the right password', async () => {
    const ids = ['alice', 'ALICE', 'Alice'];
    for (const [i, id] of ids.entries()) await auth.authenticate(id, 'wrong-password-1', `10.0.0.${i + 1}`);
    expect(await auth.authenticate('alice', PASSWORD, '10.9.9.9')).toEqual({ ok: false, reason: 'rate_limited' });
  });

  it('rate-limits per ip across usernames', async () => {
    for (let i = 0; i < 5; i++) await auth.authenticate(`user${i}`, 'wrong-password-1', '10.0.0.7');
    expect(await auth.authenticate('alice', PASSWORD, '10.0.0.7')).toEqual({ ok: false, reason: 'rate_limited' });
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.8')).ok).toBe(true);
  });

  it('caps concurrent attempts for one user at maxPerUser', async () => {
    const total = 3 + 5; // maxPerUser + 5
    const results = await Promise.all(
      Array.from({ length: total }, (_, i) => auth.authenticate('alice', 'wrong-password-1', `10.1.0.${i + 1}`)),
    );
    const reasons = results.map((r) => (r.ok ? 'ok' : r.reason));
    const invalid = reasons.filter((r) => r === 'invalid_credentials').length;
    expect(invalid).toBeLessThanOrEqual(3);
    expect(reasons.filter((r) => r === 'rate_limited').length).toBe(total - invalid);
  });

  it('clears the per-user counter after a successful login', async () => {
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.1')).ok).toBe(true);
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    await auth.authenticate('alice', 'wrong-password-1', '10.0.0.1');
    expect((await auth.authenticate('alice', PASSWORD, '10.0.0.1')).ok).toBe(true);
  });
});
