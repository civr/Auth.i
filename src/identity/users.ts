import type { Selectable } from 'kysely';
import { hashPassword } from '../crypto/passwords.js';
import type { Db } from '../db/db.js';
import type { UsersTable } from '../db/schema.js';
import { ConflictError, NotFoundError, isUniqueViolation } from '../errors.js';
import type { EventBus } from '../events/bus.js';
import { escapeLike, isUuid } from '../util.js';

export interface User {
  id: string;
  username: string;
  email: string | null;
  displayName: string;
  givenName: string | null;
  familyName: string | null;
  isActive: boolean;
  isAdmin: boolean;
  hasPassword: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  username: string;
  email?: string | null;
  displayName?: string;
  givenName?: string | null;
  familyName?: string | null;
  isAdmin?: boolean;
  isActive?: boolean;
  password?: string;
}

export type UpdateUserInput = Partial<Omit<CreateUserInput, 'password'>>;

export function toUser(row: Selectable<UsersTable>): User {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    displayName: row.display_name,
    givenName: row.given_name,
    familyName: row.family_name,
    isActive: row.is_active,
    isAdmin: row.is_admin,
    hasPassword: row.password_hash !== null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'A user with this username or email already exists';

export class UserService {
  constructor(
    private readonly db: Db,
    private readonly events: EventBus,
  ) {}

  async create(input: CreateUserInput): Promise<User> {
    const passwordHash = input.password ? await hashPassword(input.password) : null;
    let row: Selectable<UsersTable>;
    try {
      row = await this.db
        .insertInto('users')
        .values({
          username: input.username,
          email: input.email ?? null,
          display_name: input.displayName ?? input.username,
          given_name: input.givenName ?? null,
          family_name: input.familyName ?? null,
          is_admin: input.isAdmin ?? false,
          is_active: input.isActive ?? true,
          password_hash: passwordHash,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    await this.events.publish({ type: 'user.created', userId: row.id });
    return toUser(row);
  }

  async get(id: string): Promise<User | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('users').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toUser(row) : null;
  }

  async findByLogin(identifier: string): Promise<{ user: User; passwordHash: string | null } | null> {
    const value = identifier.trim().toLowerCase();
    if (!value) return null;
    const row = await this.db
      .selectFrom('users')
      .selectAll()
      .where((eb) =>
        eb.or([eb(eb.fn('lower', ['username']), '=', value), eb(eb.fn('lower', ['email']), '=', value)]),
      )
      .orderBy('created_at')
      .executeTakeFirst();
    return row ? { user: toUser(row), passwordHash: row.password_hash } : null;
  }

  async list(opts: { search?: string; limit?: number; offset?: number } = {}): Promise<User[]> {
    let query = this.db
      .selectFrom('users')
      .selectAll()
      .orderBy('username')
      .limit(opts.limit ?? 50)
      .offset(opts.offset ?? 0);
    if (opts.search) {
      const pattern = `%${escapeLike(opts.search)}%`;
      query = query.where((eb) =>
        eb.or([
          eb('username', 'ilike', pattern),
          eb('email', 'ilike', pattern),
          eb('display_name', 'ilike', pattern),
        ]),
      );
    }
    return (await query.execute()).map(toUser);
  }

  async count(): Promise<number> {
    const { n } = await this.db
      .selectFrom('users')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .executeTakeFirstOrThrow();
    return Number(n);
  }

  async update(id: string, input: UpdateUserInput): Promise<User> {
    const before = await this.get(id);
    if (!before) throw new NotFoundError('User not found');
    const patch = {
      ...(input.username !== undefined && { username: input.username }),
      ...(input.email !== undefined && { email: input.email }),
      ...(input.displayName !== undefined && { display_name: input.displayName }),
      ...(input.givenName !== undefined && { given_name: input.givenName }),
      ...(input.familyName !== undefined && { family_name: input.familyName }),
      ...(input.isAdmin !== undefined && { is_admin: input.isAdmin }),
      ...(input.isActive !== undefined && { is_active: input.isActive }),
    };
    if (Object.keys(patch).length === 0) return before;
    let row: Selectable<UsersTable>;
    try {
      row = await this.db
        .updateTable('users')
        .set({ ...patch, updated_at: new Date() })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
    const deactivated = before.isActive && !row.is_active;
    await this.events.publish({ type: deactivated ? 'user.deactivated' : 'user.updated', userId: id });
    return toUser(row);
  }

  async setPassword(id: string, password: string | null): Promise<void> {
    const passwordHash = password === null ? null : await hashPassword(password);
    const result = isUuid(id)
      ? await this.db
          .updateTable('users')
          .set({ password_hash: passwordHash, updated_at: new Date() })
          .where('id', '=', id)
          .executeTakeFirst()
      : undefined;
    if (!result || result.numUpdatedRows === 0n) throw new NotFoundError('User not found');
  }

  async delete(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('users').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('User not found');
    await this.events.publish({ type: 'user.deleted', userId: id });
  }

  async groupNames(userId: string): Promise<string[]> {
    if (!isUuid(userId)) return [];
    const rows = await this.db
      .selectFrom('group_members')
      .innerJoin('groups', 'groups.id', 'group_members.group_id')
      .select('groups.name')
      .where('group_members.user_id', '=', userId)
      .orderBy('groups.name')
      .execute();
    return rows.map((r) => r.name);
  }
}
