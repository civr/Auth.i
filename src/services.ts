import { ApiTokenService } from './api/tokens.js';
import { ApplicationService } from './apps/applications.js';
import { AuditLog } from './audit/audit.js';
import { LocalAuthenticator } from './auth/local-login.js';
import { LoginRateLimiter } from './auth/rate-limit.js';
import { SessionService } from './auth/sessions.js';
import type { Config } from './config.js';
import { createSecretBox, type SecretBox } from './crypto/secrets.js';
import type { Db } from './db/db.js';
import { EventBus, type DomainEvent } from './events/bus.js';
import { GroupService } from './identity/groups.js';
import { UserService } from './identity/users.js';

export interface Services {
  config: Config;
  db: Db;
  box: SecretBox;
  events: EventBus;
  audit: AuditLog;
  users: UserService;
  groups: GroupService;
  sessions: SessionService;
  limiter: LoginRateLimiter;
  localAuth: LocalAuthenticator;
  apps: ApplicationService;
  apiTokens: ApiTokenService;
}

export interface ServiceLogger {
  error(obj: object, msg?: string): void;
}

export function createServices(
  config: Config,
  db: Db,
  opts: { onEventError?: (err: unknown, event: DomainEvent) => void; logger?: ServiceLogger } = {},
): Services {
  const box = createSecretBox(config.secretKey);
  // Failing event handlers must never vanish silently: log them unless the caller handles them.
  const onEventError =
    opts.onEventError ??
    ((err: unknown, event: DomainEvent) => {
      const logger: ServiceLogger = opts.logger ?? {
        error: (obj, msg) => console.error(msg, obj),
      };
      logger.error({ err, event }, 'event handler failed');
    });
  const events = new EventBus(onEventError);
  const audit = new AuditLog(db);
  const users = new UserService(db, events);
  const groups = new GroupService(db, events);
  const sessions = new SessionService(db);
  const limiter = new LoginRateLimiter(db);
  const localAuth = new LocalAuthenticator(users, limiter, audit);
  const apps = new ApplicationService(db, box, groups);
  const apiTokens = new ApiTokenService(db);
  return { config, db, box, events, audit, users, groups, sessions, limiter, localAuth, apps, apiTokens };
}
