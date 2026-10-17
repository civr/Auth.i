import type { Db } from '../db/db.js';

export interface RateLimitOptions {
  windowMs: number;
  maxPerIp: number;
  maxPerUser: number;
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

  async isBlocked(ip: string, identifier: string): Promise<boolean> {
    const since = new Date(Date.now() - this.opts.windowMs);
    const rows = await this.db
      .selectFrom('login_attempts')
      .select(['key', (eb) => eb.fn.countAll<string>().as('n')])
      .where('key', 'in', [ipKey(ip), userKey(identifier)])
      .where('at', '>', since)
      .groupBy('key')
      .execute();
    return rows.some((r) =>
      r.key === ipKey(ip) ? Number(r.n) >= this.opts.maxPerIp : Number(r.n) >= this.opts.maxPerUser,
    );
  }

  async recordFailure(ip: string, identifier: string): Promise<void> {
    await this.db
      .insertInto('login_attempts')
      .values([{ key: ipKey(ip) }, { key: userKey(identifier) }])
      .execute();
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
