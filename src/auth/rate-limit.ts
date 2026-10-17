import type { Db } from '../db/db.js';

export interface RateLimitOptions {
  windowMs: number;
  maxPerIp: number;
  maxPerUser: number;
}

export interface Reservation {
  /** True when the reserved attempt (counted with the window's existing attempts) exceeds a limit. */
  blocked: boolean;
  /** Ids of the attempt rows this request reserved; release them on success. */
  ids: string[];
}

const DEFAULTS: RateLimitOptions = { windowMs: 15 * 60 * 1000, maxPerIp: 30, maxPerUser: 10 };

const ipKey = (ip: string) => `ip:${ip}`;
const userKey = (identifier: string) => `user:${identifier.trim().toLowerCase()}`;

export class LoginRateLimiter {
  private readonly opts: RateLimitOptions;

  constructor(
    private readonly db: Db,
    opts: Partial<RateLimitOptions> = {},
  ) {
    this.opts = { ...DEFAULTS, ...opts };
  }

  /**
   * Reserves one attempt for the IP and one for the user, then counts the window including them.
   * Reserving before the password check means concurrent requests cannot all read a low count.
   * Rows are kept on block and on failure (they are the failed attempts); callers release them on success.
   */
  async reserve(ip: string, identifier: string): Promise<Reservation> {
    const now = new Date();
    const since = new Date(now.getTime() - this.opts.windowMs);
    const [ipRow, userRow] = await this.db
      .insertInto('login_attempts')
      .values([
        { key: ipKey(ip), at: now },
        { key: userKey(identifier), at: now },
      ])
      .returning('id')
      .execute();
    const rows = await this.db
      .selectFrom('login_attempts')
      .select(['key', (eb) => eb.fn.countAll<string>().as('n')])
      .where('key', 'in', [ipKey(ip), userKey(identifier)])
      .where('at', '>', since)
      .groupBy('key')
      .execute();
    const count = (key: string) => Number(rows.find((r) => r.key === key)?.n ?? 0);
    const blocked =
      count(ipKey(ip)) > this.opts.maxPerIp || count(userKey(identifier)) > this.opts.maxPerUser;
    return { blocked, ids: [ipRow!.id, userRow!.id] };
  }

  /** Deletes attempt rows reserved by a request that succeeded. */
  async release(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    await this.db.deleteFrom('login_attempts').where('id', 'in', ids).execute();
  }

  async clear(identifier: string): Promise<void> {
    await this.db.deleteFrom('login_attempts').where('key', '=', userKey(identifier)).execute();
  }

  async purge(): Promise<void> {
    await this.db
      .deleteFrom('login_attempts')
      .where('at', '<', new Date(Date.now() - this.opts.windowMs))
      .execute();
  }
}
