import { sql, type Selectable } from 'kysely';
import type { Db } from '../db/db.js';
import type { GroupsTable } from '../db/schema.js';
import { ConflictError, NotFoundError, isForeignKeyViolation, isUniqueViolation } from '../errors.js';
import type { EventBus } from '../events/bus.js';
import { isUuid } from '../util.js';
import { toUser, type User } from './users.js';

export interface Group {
  id: string;
  name: string;
  description: string;
  sourceId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

function toGroup(row: Selectable<GroupsTable>): Group {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    sourceId: row.source_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'A group with this name already exists';

export class GroupService {
  constructor(
    private readonly db: Db,
    private readonly events: EventBus,
  ) {}

  async create(input: { name: string; description?: string }): Promise<Group> {
    let row: Selectable<GroupsTable>;
    try {
      row = await this.db
        .insertInto('groups')
        .values({ name: input.name, description: input.description ?? '', source_id: null, external_id: null })
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'group.created', groupId: row.id });
    return toGroup(row);
  }

  async get(id: string): Promise<Group | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('groups').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toGroup(row) : null;
  }

  async list(): Promise<Group[]> {
    return (await this.db.selectFrom('groups').selectAll().orderBy('name').execute()).map(toGroup);
  }

  async update(id: string, input: { name?: string; description?: string }): Promise<Group> {
    const existing = await this.get(id);
    if (!existing) throw new NotFoundError('Group not found');
    const patch = {
      ...(input.name !== undefined && { name: input.name }),
      ...(input.description !== undefined && { description: input.description }),
    };
    if (Object.keys(patch).length === 0) return existing;
    let row: Selectable<GroupsTable>;
    try {
      row = await this.db
        .updateTable('groups')
        .set({ ...patch, updated_at: new Date() })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'group.updated', groupId: id });
    return toGroup(row);
  }

  async delete(id: string): Promise<void> {
    const group = await this.get(id);
    if (!group) throw new NotFoundError('Group not found');
    await this.db.transaction().execute(async (trx) => {
      await trx
        .updateTable('applications')
        .set({ allowed_group_ids: sql<string[]>`array_remove(allowed_group_ids, ${id}::uuid)` })
        .where(sql<boolean>`${id}::uuid = ANY(allowed_group_ids)`)
        .execute();
      await trx.deleteFrom('groups').where('id', '=', id).execute();
    });
    await this.events.publish({ type: 'group.deleted', groupId: id, name: group.name });
  }

  async listMembers(groupId: string): Promise<User[]> {
    if (!isUuid(groupId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('users', 'users.id', 'group_members.user_id')
      .selectAll('users')
      .where('group_members.group_id', '=', groupId)
      .orderBy('users.username')
      .execute();
    return rows.map(toUser);
  }

  async addMember(groupId: string, userId: string): Promise<void> {
    if (!isUuid(groupId) || !isUuid(userId)) throw new NotFoundError('User or group not found');
    let inserted: bigint;
    try {
      const result = await this.db
        .insertInto('group_members')
        .values({ group_id: groupId, user_id: userId })
        .onConflict((oc) => oc.doNothing())
        .executeTakeFirst();
      inserted = result.numInsertedOrUpdatedRows ?? 0n;
    } catch (err) {
      if (isForeignKeyViolation(err)) throw new NotFoundError('User or group not found');
      throw err;
    }
    if (inserted > 0n) {
      await this.events.publish({ type: 'group.members_changed', groupId, userIds: [userId] });
    }
  }

  async removeMember(groupId: string, userId: string): Promise<void> {
    if (!isUuid(groupId) || !isUuid(userId)) return;
    const result = await this.db
      .deleteFrom('group_members')
      .where('group_id', '=', groupId)
      .where('user_id', '=', userId)
      .executeTakeFirst();
    if (result.numDeletedRows > 0n) {
      await this.events.publish({ type: 'group.members_changed', groupId, userIds: [userId] });
    }
  }

  async groupsForUser(userId: string): Promise<Group[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('groups', 'groups.id', 'group_members.group_id')
      .selectAll('groups')
      .where('group_members.user_id', '=', userId)
      .orderBy('groups.name')
      .execute();
    return rows.map(toGroup);
  }

  async groupIdsForUser(userId: string): Promise<string[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .select('group_id')
      .where('user_id', '=', userId)
      .execute();
    return rows.map((r) => r.group_id);
  }

  async countExisting(ids: string[]): Promise<number> {
    const valid = ids.filter(isUuid);
    if (valid.length === 0) return 0;
    const { n } = await this.db
      .selectFrom('groups')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .where('id', 'in', valid)
      .executeTakeFirstOrThrow();
    return Number(n);
  }
}
