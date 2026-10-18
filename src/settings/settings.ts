import { isIP } from 'node:net';
import type { Actor, AuditLog } from '../audit/audit.js';
import type { Config } from '../config.js';
import type { Db } from '../db/db.js';
import type { EventBus } from '../events/bus.js';
import { LOG_LEVELS, SETTING_ENV, SETTING_KEYS, type SettingKey } from './keys.js';

export interface EffectiveSettings {
  issuerUrl: string;
  cookieDomain: string | undefined;
  secureCookies: boolean;
  trustProxy: string;
  logLevel: string;
}

export interface SettingInfo {
  key: SettingKey;
  value: string;
  locked: boolean;
  envVar: string;
  source: 'env' | 'database' | 'default';
}

export type SettingsPatch = Partial<Record<SettingKey, string>>;

export class SettingsValidationError extends Error {
  constructor(readonly fieldErrors: Partial<Record<SettingKey, string>>) {
    super('Invalid settings');
    this.name = 'SettingsValidationError';
  }
}

const PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normaliseIssuerUrl(raw: string): string {
  const value = raw.trim();
  if (/[\s\u0000-\u001f\u007f]/.test(value)) throw new Error('must not contain spaces or control characters');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('must be a full URL such as https://auth.example.com');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('must start with https:// or http://');
  if (url.username || url.password) throw new Error('must not contain a username or password');
  if (url.pathname !== '/' || url.search || url.hash) throw new Error('must not contain a path, query or fragment');
  return `${url.protocol}//${url.host}`;
}

function hostOf(issuerUrl: string): string {
  return new URL(issuerUrl).hostname.toLowerCase();
}

export function normaliseCookieDomain(raw: string, issuerUrl: string): string | undefined {
  const domain = raw.trim().toLowerCase().replace(/^\.+/, '');
  if (domain === '') return undefined;
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) throw new Error('must be a domain such as example.com');
  const host = hostOf(issuerUrl);
  if (host !== domain && !host.endsWith(`.${domain}`)) {
    throw new Error(`must be ${host} or a parent domain of it`);
  }
  return domain;
}

function validTrustEntry(entry: string): boolean {
  if (PRESETS.has(entry)) return true;
  const [ip, prefix, extra] = entry.split('/');
  if (extra !== undefined || !ip) return false;
  const family = isIP(ip);
  if (family === 0) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (family === 4 ? 32 : 128);
}

export function normaliseTrustProxy(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (value === 'true' || value === 'false') return value;
  const entries = value.split(',').map((e) => e.trim()).filter(Boolean);
  if (entries.length === 0) throw new Error('enter true, false, or a list of addresses');
  const bad = entries.find((e) => !validTrustEntry(e));
  if (bad) throw new Error(`"${bad}" is not an IP address, CIDR range, or loopback/linklocal/uniquelocal`);
  return entries.join(',');
}

export function normaliseLogLevel(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (!(LOG_LEVELS as readonly string[]).includes(value)) throw new Error(`must be one of ${LOG_LEVELS.join(', ')}`);
  return value;
}

export class SettingsService {
  #stored = new Map<SettingKey, string>();

  constructor(
    private readonly db: Db,
    private readonly config: Config,
    private readonly events: EventBus,
    private readonly audit: AuditLog,
  ) {}

  async load(): Promise<void> {
    const rows = await this.db.selectFrom('settings').select(['key', 'value']).execute();
    const next = new Map<SettingKey, string>();
    for (const row of rows) {
      if ((SETTING_KEYS as readonly string[]).includes(row.key) && typeof row.value === 'string') {
        next.set(row.key as SettingKey, row.value);
      }
    }
    this.#stored = next;
  }

  isLocked(key: SettingKey): boolean {
    return this.config.settingsFromEnv.has(key);
  }

  #configValue(key: SettingKey): string | undefined {
    switch (key) {
      case 'issuerUrl':
        return this.config.issuerUrl;
      case 'cookieDomain':
        return this.config.cookieDomain;
      case 'trustProxy':
        return this.config.trustProxy;
      case 'logLevel':
        return this.config.logLevel;
    }
  }

  #value(key: SettingKey): string | undefined {
    if (this.isLocked(key)) return this.#configValue(key);
    return this.#stored.has(key) ? this.#stored.get(key) : this.#configValue(key);
  }

  current(): EffectiveSettings {
    const issuerUrl = this.#value('issuerUrl')!;
    const cookieDomain = this.#value('cookieDomain') || undefined;
    return {
      issuerUrl,
      cookieDomain,
      secureCookies: issuerUrl.startsWith('https://'),
      trustProxy: this.#value('trustProxy')!,
      logLevel: this.#value('logLevel')!,
    };
  }

  describe(): SettingInfo[] {
    return SETTING_KEYS.map((key) => ({
      key,
      value: this.#value(key) ?? '',
      locked: this.isLocked(key),
      envVar: SETTING_ENV[key],
      source: this.isLocked(key) ? 'env' : this.#stored.has(key) ? 'database' : 'default',
    }));
  }

  /** Normalises a patch against the current values; throws SettingsValidationError listing every bad field. */
  validate(patch: SettingsPatch): SettingsPatch {
    const errors: Partial<Record<SettingKey, string>> = {};
    const out: SettingsPatch = {};
    const issuerForDomain = (): string => out.issuerUrl ?? this.current().issuerUrl;
    for (const key of SETTING_KEYS) {
      const raw = patch[key];
      if (raw === undefined) continue;
      if (this.isLocked(key)) {
        if (raw.trim() !== (this.#value(key) ?? '')) errors[key] = `Set by ${SETTING_ENV[key]}`;
        continue;
      }
      try {
        if (key === 'issuerUrl') out.issuerUrl = normaliseIssuerUrl(raw);
        if (key === 'trustProxy') out.trustProxy = normaliseTrustProxy(raw);
        if (key === 'logLevel') out.logLevel = normaliseLogLevel(raw);
      } catch (e) {
        errors[key] = (e as Error).message;
      }
    }
    if (patch.cookieDomain !== undefined && !this.isLocked('cookieDomain') && !errors.issuerUrl) {
      try {
        out.cookieDomain = normaliseCookieDomain(patch.cookieDomain, issuerForDomain()) ?? '';
      } catch (e) {
        errors.cookieDomain = (e as Error).message;
      }
    }
    if (Object.keys(errors).length > 0) throw new SettingsValidationError(errors);
    return out;
  }

  async update(patch: SettingsPatch, actor: Actor, ip?: string): Promise<SettingKey[]> {
    const normalised = this.validate(patch);
    const changes: Partial<Record<SettingKey, { from: string; to: string }>> = {};
    for (const key of SETTING_KEYS) {
      const to = normalised[key];
      if (to === undefined) continue;
      const from = this.#value(key) ?? '';
      if (from !== to) changes[key] = { from, to };
    }
    const changed = Object.keys(changes) as SettingKey[];
    if (changed.length === 0) return [];
    const updatedBy = actor.type === 'user' ? actor.id : null;
    await this.db.transaction().execute(async (trx) => {
      for (const key of changed) {
        await trx
          .insertInto('settings')
          .values({ key, value: JSON.stringify(changes[key]!.to), updated_by: updatedBy })
          .onConflict((oc) =>
            oc.column('key').doUpdateSet({ value: JSON.stringify(changes[key]!.to), updated_at: new Date(), updated_by: updatedBy }),
          )
          .execute();
      }
    });
    await this.load();
    await this.audit.record({ actor, action: 'settings.update', details: { changes }, ...(ip ? { ip } : {}) });
    await this.events.publish({ type: 'settings.changed', keys: changed });
    return changed;
  }
}
