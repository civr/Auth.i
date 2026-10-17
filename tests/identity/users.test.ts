import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConflictError, NotFoundError } from '../../src/errors.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let events: DomainEvent[];

beforeEach(async () => {
  t = await createTestDb();
  const bus = new EventBus();
  events = [];
  bus.subscribe((e) => {
    events.push(e);
  });
  users = new UserService(t.db, bus);
});
afterEach(() => t.destroy());

describe('UserService', () => {
  it('creates a user with defaults and emits user.created', async () => {
    const u = await users.create({ username: 'alice', email: 'alice@example.com', password: 'correct-horse-battery' });
    expect(u).toMatchObject({
      username: 'alice',
      email: 'alice@example.com',
      displayName: 'alice',
      isActive: true,
      isAdmin: false,
      hasPassword: true,
    });
    expect(events).toEqual([{ type: 'user.created', userId: u.id }]);
  });

  it('rejects duplicate usernames and emails case-insensitively', async () => {
    await users.create({ username: 'alice', email: 'alice@example.com' });
    await expect(users.create({ username: 'ALICE' })).rejects.toBeInstanceOf(ConflictError);
    await expect(users.create({ username: 'bob', email: 'Alice@Example.com' })).rejects.toBeInstanceOf(ConflictError);
  });

  it('finds users by username or email in any case', async () => {
    const u = await users.create({ username: 'alice', email: 'alice@example.com', password: 'correct-horse-battery' });
    expect((await users.findByLogin('ALICE'))?.user.id).toBe(u.id);
    expect((await users.findByLogin('Alice@Example.COM'))?.user.id).toBe(u.id);
    expect((await users.findByLogin('alice'))?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(await users.findByLogin('nobody')).toBeNull();
  });

  it('returns null for unknown or malformed ids', async () => {
    expect(await users.get('00000000-0000-0000-0000-000000000000')).toBeNull();
    expect(await users.get('not-a-uuid')).toBeNull();
  });

  it('updates and emits user.updated, or user.deactivated on deactivation', async () => {
    const u = await users.create({ username: 'alice' });
    events.length = 0;
    const updated = await users.update(u.id, { displayName: 'Alice A.' });
    expect(updated.displayName).toBe('Alice A.');
    const deactivated = await users.update(u.id, { isActive: false });
    expect(deactivated.isActive).toBe(false);
    expect(events).toEqual([
      { type: 'user.updated', userId: u.id },
      { type: 'user.deactivated', userId: u.id },
    ]);
  });

  it('throws NotFoundError when updating a missing user', async () => {
    await expect(users.update('00000000-0000-0000-0000-000000000000', { displayName: 'x' })).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('maps unique violations on update to ConflictError', async () => {
    await users.create({ username: 'alice' });
    const bob = await users.create({ username: 'bob' });
    await expect(users.update(bob.id, { username: 'Alice' })).rejects.toBeInstanceOf(ConflictError);
  });

  it('lists with a search that treats wildcards literally', async () => {
    await users.create({ username: 'alice', displayName: 'Alice 100%' });
    await users.create({ username: 'bob' });
    expect((await users.list()).map((u) => u.username)).toEqual(['alice', 'bob']);
    expect((await users.list({ search: '100%' })).map((u) => u.username)).toEqual(['alice']);
    expect(await users.list({ search: '%' })).toHaveLength(1);
    expect(await users.count()).toBe(2);
  });

  it('sets and clears passwords', async () => {
    const u = await users.create({ username: 'alice' });
    await users.setPassword(u.id, 'correct-horse-battery');
    expect((await users.get(u.id))?.hasPassword).toBe(true);
    await users.setPassword(u.id, null);
    expect((await users.get(u.id))?.hasPassword).toBe(false);
  });

  it('deletes users and emits user.deleted', async () => {
    const u = await users.create({ username: 'alice' });
    await users.delete(u.id);
    expect(await users.get(u.id)).toBeNull();
    expect(events.at(-1)).toEqual({ type: 'user.deleted', userId: u.id });
    await expect(users.delete(u.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
