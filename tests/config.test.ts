import { describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';

const key = Buffer.alloc(32, 7).toString('base64');
const base = {
  KEYSTONE_ISSUER_URL: 'https://auth.example.com/',
  KEYSTONE_SECRET_KEY: key,
  DATABASE_URL: 'postgres://keystone:keystone@db/keystone',
};
const withoutSecret = {
  KEYSTONE_ISSUER_URL: 'https://auth.example.com/',
  DATABASE_URL: 'postgres://keystone:keystone@db/keystone',
};

describe('loadConfig', () => {
  it('parses a minimal environment and applies defaults', () => {
    const c = loadConfig(base);
    expect(c.issuerUrl).toBe('https://auth.example.com');
    expect(c.secureCookies).toBe(true);
    expect(c.port).toBe(9000);
    expect(c.secretKey).toHaveLength(32);
    expect(c.cookieDomain).toBeUndefined();
    expect(c.bootstrapAdmin).toBeUndefined();
    expect(c.trustProxy).toBe('loopback,linklocal,uniquelocal');
  });

  it('treats empty strings as unset', () => {
    const c = loadConfig({ ...base, KEYSTONE_COOKIE_DOMAIN: '', KEYSTONE_BOOTSTRAP_ADMIN_USER: '' });
    expect(c.cookieDomain).toBeUndefined();
    expect(c.bootstrapAdmin).toBeUndefined();
  });

  it('rejects a secret key that is not 32 bytes', () => {
    expect(() => loadConfig({ ...base, KEYSTONE_SECRET_KEY: 'c2hvcnQ=' })).toThrow(/KEYSTONE_SECRET_KEY/);
  });

  it('generates and reuses a persistent secret key when none is provided', () => {
    const dataDir = mkdtempSync(path.join(tmpdir(), 'keystone-config-'));
    try {
      const first = loadConfig(withoutSecret, { dataDir });
      const second = loadConfig(withoutSecret, { dataDir });
      expect(first.secretKey).toHaveLength(32);
      expect(second.secretKey).toEqual(first.secretKey);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('uses local defaults with only the persisted database password', () => {
    const dataDir = mkdtempSync(path.join(tmpdir(), 'keystone-defaults-'));
    try {
      writeFileSync(path.join(dataDir, 'postgres-password'), 'local-password\n');
      const c = loadConfig({}, { dataDir });
      expect(c.issuerUrl).toBe('http://localhost:9000');
      expect(c.databaseUrl).toBe('postgres://keystone:local-password@postgres:5432/keystone');
      expect(c.secretKey).toHaveLength(32);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('requires a bootstrap password when a bootstrap user is set', () => {
    expect(() => loadConfig({ ...base, KEYSTONE_BOOTSTRAP_ADMIN_USER: 'admin' })).toThrow(
      /KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD/,
    );
  });

  it('builds the bootstrap admin', () => {
    const c = loadConfig({
      ...base,
      KEYSTONE_BOOTSTRAP_ADMIN_USER: 'admin',
      KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD: 'correct-horse-battery',
      KEYSTONE_BOOTSTRAP_ADMIN_EMAIL: 'admin@example.com',
    });
    expect(c.bootstrapAdmin).toEqual({
      username: 'admin',
      password: 'correct-horse-battery',
      email: 'admin@example.com',
    });
  });

  it('uses insecure cookies for an http issuer', () => {
    expect(loadConfig({ ...base, KEYSTONE_ISSUER_URL: 'http://localhost:9000' }).secureCookies).toBe(false);
  });

  it('records which settings come from the environment', () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'keystone-settings-env-'));
    try {
      const c = loadConfig(
        { KEYSTONE_ISSUER_URL: 'https://a.example.test', LOG_LEVEL: 'debug', KEYSTONE_COOKIE_DOMAIN: '', DATABASE_URL: base.DATABASE_URL },
        { dataDir: tmp },
      );
      expect([...c.settingsFromEnv].sort()).toEqual(['issuerUrl', 'logLevel']);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('rejects non-http issuer URLs', () => {
    expect(() => loadConfig({ ...base, KEYSTONE_ISSUER_URL: 'ftp://auth.example.com' })).toThrow(/KEYSTONE_ISSUER_URL/);
  });
});
