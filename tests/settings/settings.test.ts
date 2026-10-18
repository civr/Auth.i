import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit/audit.js';
import { EventBus, type DomainEvent } from '../../src/events/bus.js';
import { SettingsService, SettingsValidationError } from '../../src/settings/settings.js';
import type { SettingKey } from '../../src/settings/keys.js';
import { testConfig } from '../helpers/app.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let events: DomainEvent[];

function make(locked: SettingKey[] = [], overrides = {}) {
  const bus = new EventBus();
  bus.subscribe((e) => void events.push(e));
  const config = testConfig({ settingsFromEnv: new Set(locked), issuerUrl: 'http://localhost:9000', ...overrides });
  return new SettingsService(t.db, config, bus, new AuditLog(t.db));
}
const actor = { type: 'system' } as const;

beforeEach(async () => {
  t = await createTestDb();
  events = [];
});
afterEach(() => t.destroy());

describe('SettingsService', () => {
  it('uses defaults when nothing is stored', async () => {
    const s = make();
    await s.load();
    expect(s.current()).toEqual({
      issuerUrl: 'http://localhost:9000',
      cookieDomain: undefined,
      secureCookies: false,
      trustProxy: 'loopback',
      logLevel: 'silent',
    });
    expect(s.describe().find((i) => i.key === 'issuerUrl')).toMatchObject({ source: 'default', locked: false });
  });

  it('stores, normalises and reloads values', async () => {
    const s = make();
    await s.load();
    const changed = await s.update({ issuerUrl: 'HTTPS://Auth.Example.TEST/', cookieDomain: '.Example.test' }, actor);
    expect(changed.sort()).toEqual(['cookieDomain', 'issuerUrl']);
    expect(s.current()).toMatchObject({ issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test', secureCookies: true });
    const again = make();
    await again.load();
    expect(again.current().issuerUrl).toBe('https://auth.example.test');
    expect(again.describe().find((i) => i.key === 'issuerUrl')).toMatchObject({ source: 'database' });
    expect(events).toEqual([{ type: 'settings.changed', keys: expect.arrayContaining(['issuerUrl', 'cookieDomain']) }]);
  });

  it('lets env override the database and rejects updates to locked keys', async () => {
    const s = make(['issuerUrl'], { issuerUrl: 'https://env.example.test' });
    await s.load();
    expect(s.current().issuerUrl).toBe('https://env.example.test');
    await expect(s.update({ issuerUrl: 'https://other.example.test', logLevel: 'debug' }, actor)).rejects.toMatchObject({
      fieldErrors: { issuerUrl: 'Set by KEYSTONE_ISSUER_URL' },
    });
    expect(s.current().logLevel).toBe('silent'); // nothing partially saved
  });

  it.each([
    ['issuerUrl', 'ftp://x.example.test'],
    ['issuerUrl', 'https://x.example.test/path'],
    ['issuerUrl', 'https://x.example.test/?a=1'],
    ['issuerUrl', 'https://user:pw@x.example.test'],
    ['issuerUrl', 'not a url'],
    ['cookieDomain', 'evil.com'],
    ['cookieDomain', 'com'],
    ['trustProxy', '10.0.0.0/99'],
    ['trustProxy', 'loopback,banana'],
    ['logLevel', 'loud'],
  ])('rejects invalid %s %s', async (key, value) => {
    const s = make();
    await s.load();
    await s.update({ issuerUrl: 'https://auth.example.test' }, actor);
    const err = await s.update({ [key]: value }, actor).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SettingsValidationError);
    expect((err as SettingsValidationError).fieldErrors[key as SettingKey]).toBeTruthy();
  });

  it('accepts valid trust proxy forms and clears the cookie domain with an empty value', async () => {
    const s = make();
    await s.load();
    await s.update({ issuerUrl: 'https://auth.example.test', cookieDomain: 'example.test' }, actor);
    await s.update({ trustProxy: 'true' }, actor);
    await s.update({ trustProxy: '127.0.0.1, 10.0.0.0/8, ::1, fd00::/8, loopback' }, actor);
    expect(s.current().trustProxy).toBe('127.0.0.1,10.0.0.0/8,::1,fd00::/8,loopback');
    await s.update({ cookieDomain: '' }, actor);
    expect(s.current().cookieDomain).toBeUndefined();
  });

  it('returns no changed keys and emits nothing when values are unchanged', async () => {
    const s = make();
    await s.load();
    expect(await s.update({ logLevel: 'silent' }, actor)).toEqual([]);
    expect(events).toEqual([]);
  });

  it('records an audit entry with old and new values', async () => {
    const s = make();
    await s.load();
    await s.update({ logLevel: 'debug' }, actor);
    const rows = await t.db.selectFrom('audit_log').selectAll().where('action', '=', 'settings.update').execute();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.details).toEqual({ changes: { logLevel: { from: 'silent', to: 'debug' } } });
  });
});
