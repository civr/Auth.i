import type { AuditLog } from '../audit/audit.js';
import { verifyPassword } from '../crypto/passwords.js';
import type { User, UserService } from '../identity/users.js';
import type { LoginRateLimiter } from './rate-limit.js';

export type LoginResult =
  | { ok: true; user: User }
  | { ok: false; reason: 'invalid_credentials' | 'inactive' | 'rate_limited' };

export class LocalAuthenticator {
  constructor(
    private readonly users: UserService,
    private readonly limiter: LoginRateLimiter,
    private readonly audit: AuditLog,
  ) {}

  async authenticate(identifier: string, password: string, ip: string): Promise<LoginResult> {
    const id = identifier.trim();
    if (await this.limiter.isBlocked(ip, id)) {
      await this.audit.record({ actor: { type: 'anonymous' }, action: 'login.rate_limited', details: { identifier: id }, ip });
      return { ok: false, reason: 'rate_limited' };
    }
    const found = await this.users.findByLogin(id);
    const valid = await verifyPassword(found?.passwordHash ?? null, password);
    if (!found || !valid) {
      await this.limiter.recordFailure(ip, id);
      await this.audit.record({ actor: { type: 'anonymous' }, action: 'login.failed', details: { identifier: id }, ip });
      return { ok: false, reason: 'invalid_credentials' };
    }
    if (!found.user.isActive) {
      await this.limiter.recordFailure(ip, id);
      await this.audit.record({
        actor: { type: 'user', id: found.user.id },
        action: 'login.failed',
        details: { reason: 'inactive' },
        ip,
      });
      return { ok: false, reason: 'inactive' };
    }
    await this.limiter.clear(id);
    await this.audit.record({ actor: { type: 'user', id: found.user.id }, action: 'login.success', details: { source: 'local' }, ip });
    return { ok: true, user: found.user };
  }
}
