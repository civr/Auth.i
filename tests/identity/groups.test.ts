import { sql } from 'kysely';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConflictError, NotFoundError } from '../../src/errors.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { GroupService } from '../../src/identity/groups.js';
import { UserService } from '../../src/identity/users.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let users: UserService;
let groups: GroupService;
let events: DomainEvent[];

beforeEach(async () => {
  t = await createTestDb();
  const bus = new EventBus();
  events = [];
  bus.subscribe((e) => {
    events.push(e);
  });
  users = new UserService(t.db, bus);
  groups = new GroupService(t.db, bus);
});
afterEach(() => t.destroy());

describe('GroupService', () => {
  it('creates, lists and rejects duplicate names', async () => {
    const g = await groups.create({ name: 'Staff', description: 'Everyone' });
    expect(g).toMatchObject({ name: 'Staff', description: 'Everyone', sourceId: null });
    await expect(groups.create({ name: 'staff' })).rejects.toBeInstanceOf(ConflictError);
    expect((await groups.list()).map((x) => x.name)).toEqual(['Staff']);
    expect(events).toContainEqual({ type: 'group.created', groupId: g.id });
  });

  it('adds members idempotently and emits members_changed once', async () => {
    const g = await groups.create({ name: 'staff' });
    const u = await users.create({ username: 'alice' });
    events.length = 0;
    await groups.addMember(g.id, u.id);
    await groups.addMember(g.id, u.id);
    expect(events).toEqual([{ type: 'group.members_changed', groupId: g.id, userIds: [u.id] }]);
    expect((await groups.listMembers(g.id)).map((m) => m.username)).toEqual(['alice']);
    expect(await groups.groupIdsForUser(u.id)).toEqual([g.id]);
    expect(await users.groupNames(u.id)).toEqual(['staff']);
  });

  it('removes members', async () => {
    const g = await groups.create({ name: 'staff' });
    const u = await users.create({ username: 'alice' });
    await groups.addMember(g.id, u.id);
    events.length = 0;
    await groups.removeMember(g.id, u.id);
    await groups.removeMember(g.id, u.id);
    expect(events).toEqual([{ type: 'group.members_changed', groupId: g.id, userIds: [u.id] }]);
    expect(await groups.groupIdsForUser(u.id)).toEqual([]);
  });

  it('throws NotFoundError when adding an unknown user or group', async () => {
    const g = await groups.create({ name: 'staff' });
    await expect(groups.addMember(g.id, '00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(NotFoundError);
    await expect(groups.addMember('not-a-uuid', '00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('updates and deletes, removing the group from application allow-lists', async () => {
    const g = await groups.create({ name: 'staff' });
    await sql`
      INSERT INTO applications (slug, name, client_id, client_secret_enc, allowed_group_ids)
      VALUES ('demo', 'Demo', 'demo', 'x', ARRAY[${g.id}]::uuid[])
    `.execute(t.db);
    expect((await groups.update(g.id, { name: 'crew' })).name).toBe('crew');
    await groups.delete(g.id);
    expect(await groups.get(g.id)).toBeNull();
    const app = await t.db.selectFrom('applications').select('allowed_group_ids').executeTakeFirstOrThrow();
    expect(app.allowed_group_ids).toEqual([]);
    expect(events.at(-1)).toEqual({ type: 'group.deleted', groupId: g.id, name: 'crew' });
  });

  it('counts existing group ids', async () => {
    const g = await groups.create({ name: 'staff' });
    expect(await groups.countExisting([g.id, '00000000-0000-0000-0000-000000000000', 'junk'])).toBe(1);
    expect(await groups.countExisting([])).toBe(0);
  });
});
