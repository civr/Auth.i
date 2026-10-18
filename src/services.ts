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
import { OidcProviderHolder } from './oidc/holder.js';
import { SigningKeyService } from './oidc/keys.js';
import { createOidcProvider } from './oidc/provider.js';
import { SetupService } from './setup/setup.js';
import type { SettingKey } from './settings/keys.js';
import { SettingsService } from './settings/settings.js';

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
  keys: SigningKeyService;
  oidc: OidcProviderHolder;
  settings: SettingsService;
  setup: SetupService;
  log: ServiceLogger;
}

export interface ServiceLogger {
  error(obj: object, msg?: string): void;
}

export function createServices(
  config: Config,
  db: Db,
  opts: { onEventError?: (err: unknown, event: DomainEvent) => void; logger?: ServiceLogger } = {},
): Services {
  const box = createSecretBox(config.secretKey, 'client-secrets');
  const keyBox = createSecretBox(config.secretKey, 'signing-keys');
  // Failing event handlers must never vanish silently: log them unless the caller handles them.
  const log: ServiceLogger = opts.logger ?? { error: (obj, msg) => console.error(msg, obj) };
  const onEventError =
    opts.onEventError ??
    ((err: unknown, event: DomainEvent) => {
      log.error({ err, event }, 'event handler failed');
    });
  const events = new EventBus(onEventError);
  const audit = new AuditLog(db);
  const settings = new SettingsService(db, config, events, audit);
  const users = new UserService(db, events);
  const groups = new GroupService(db, events);
  const sessions = new SessionService(db);
  const limiter = new LoginRateLimiter(db);
  const localAuth = new LocalAuthenticator(users, limiter, audit);
  const apps = new ApplicationService(db, box, groups);
  const apiTokens = new ApiTokenService(db);
  const keys = new SigningKeyService(db, keyBox);
  const setup = new SetupService({ db, users, settings, audit }, new LoginRateLimiter(db, { maxPerIp: 5, maxPerUser: 1000 }));
  const oidc = new OidcProviderHolder(() =>
    createOidcProvider({ config, db, users, groups, apps, sessions, keys, audit, settings }),
  );
  return { config, db, box, events, audit, users, groups, sessions, limiter, localAuth, apps, apiTokens, keys, oidc, settings, setup, log };
}

export async function startServices(s: Services): Promise<void> {
  await s.settings.load();
  await s.keys.ensureKeys();
  await s.oidc.load();
}

/** Applies settings that need more than a fresh read: rebuilds the OIDC provider when its inputs changed. */
export async function applySettingsChange(
  s: Services,
  changed: readonly SettingKey[],
): Promise<{ oidcReloadFailed: boolean }> {
  if (!changed.some((k) => k === 'issuerUrl' || k === 'cookieDomain')) return { oidcReloadFailed: false };
  try {
    await s.oidc.load();
    return { oidcReloadFailed: false };
  } catch (err) {
    s.log.error({ err }, 'OIDC provider reload failed; keeping the previous provider');
    return { oidcReloadFailed: true };
  }
}
