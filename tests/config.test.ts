import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

const key = Buffer.alloc(32, 7).toString('base64');
const base = {
  AUTHI_ISSUER_URL: 'https://auth.example.com/',
  AUTHI_SECRET_KEY: key,
  DATABASE_URL: 'postgres://authi:authi@db/authi',
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
    const c = loadConfig({ ...base, AUTHI_COOKIE_DOMAIN: '', AUTHI_BOOTSTRAP_ADMIN_USER: '' });
    expect(c.cookieDomain).toBeUndefined();
    expect(c.bootstrapAdmin).toBeUndefined();
  });

  it('rejects a secret key that is not 32 bytes', () => {
    expect(() => loadConfig({ ...base, AUTHI_SECRET_KEY: 'c2hvcnQ=' })).toThrow(/AUTHI_SECRET_KEY/);
  });

  it('requires a bootstrap password when a bootstrap user is set', () => {
    expect(() => loadConfig({ ...base, AUTHI_BOOTSTRAP_ADMIN_USER: 'admin' })).toThrow(
      /AUTHI_BOOTSTRAP_ADMIN_PASSWORD/,
    );
  });

  it('builds the bootstrap admin', () => {
    const c = loadConfig({
      ...base,
      AUTHI_BOOTSTRAP_ADMIN_USER: 'admin',
      AUTHI_BOOTSTRAP_ADMIN_PASSWORD: 'correct-horse-battery',
      AUTHI_BOOTSTRAP_ADMIN_EMAIL: 'admin@example.com',
    });
    expect(c.bootstrapAdmin).toEqual({
      username: 'admin',
      password: 'correct-horse-battery',
      email: 'admin@example.com',
    });
  });

  it('uses insecure cookies for an http issuer', () => {
    expect(loadConfig({ ...base, AUTHI_ISSUER_URL: 'http://localhost:9000' }).secureCookies).toBe(false);
  });

  it('rejects non-http issuer URLs', () => {
    expect(() => loadConfig({ ...base, AUTHI_ISSUER_URL: 'ftp://auth.example.com' })).toThrow(/AUTHI_ISSUER_URL/);
  });
});
