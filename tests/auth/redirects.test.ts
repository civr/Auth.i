import { describe, expect, it } from 'vitest';
import { isSafeRedirect, safeRedirectTarget, type RedirectRules } from '../../src/auth/redirects.js';

const rules: RedirectRules = {
  issuerUrl: 'https://auth.example.com',
  cookieDomain: '.example.com',
  allowedHosts: ['grafana.homelab.net'],
};

describe('isSafeRedirect', () => {
  it.each([
    '/',
    '/interaction/abc',
    '/path?x=1#y',
    'https://auth.example.com/anything',
    'https://example.com/',
    'https://app.example.com/dashboard',
    'http://app.example.com/',
    'https://deep.sub.example.com/',
    'https://GRAFANA.homelab.net/d/1',
    'HTTPS://app.example.com/x',
    'https://app.example.com\\@evil.com',
  ])('accepts %s', (target) => {
    expect(isSafeRedirect(target, rules)).toBe(true);
  });

  it.each([
    '//evil.com',
    '/\\evil.com',
    '/\t/evil.com',
    '/\n/evil.com',
    '/%09/evil.com',
    '/%0a/evil.com',
    '/%0D/evil.com',
    '/%2F%2Fevil.com',
    '/%5Cevil.com',
    '/%2fevil.com',
    'https://evil.com',
    'https://example.com.evil.com',
    'https://evilexample.com',
    'https://user:pass@app.example.com/',
    'javascript:alert(1)',
    'data:text/html,hi',
    'ftp://app.example.com',
    'relative/path',
    '',
    'https://app.example.com/\r\nSet-Cookie: a=b',
    'https:app.example.com',
    'JavaScript:alert(1)',
    ' //evil.com',
    'https://evil.com\\@app.example.com',
  ])('rejects %j', (target) => {
    expect(isSafeRedirect(target, rules)).toBe(false);
  });

  it('only allows the issuer host when no cookie domain is set', () => {
    const strict = { issuerUrl: 'https://auth.example.com' };
    expect(isSafeRedirect('https://auth.example.com/x', strict)).toBe(true);
    expect(isSafeRedirect('https://app.example.com/x', strict)).toBe(false);
  });
});

describe('isSafeRedirect edge cases', () => {
  it('rejects a bare dot cookie domain and does not match trailing-dot hosts', () => {
    const dotOnly = { issuerUrl: 'https://auth.example.com', cookieDomain: '.' };
    expect(isSafeRedirect('https://evil.com.', dotOnly)).toBe(false);
    expect(isSafeRedirect('https://app.example.com/', dotOnly)).toBe(false);
    const emptyDomain = { issuerUrl: 'https://auth.example.com', cookieDomain: '' };
    expect(isSafeRedirect('https://evil.com.', emptyDomain)).toBe(false);
  });
});

describe('safeRedirectTarget', () => {
  it('returns the canonical href for absolute targets', () => {
    expect(safeRedirectTarget('HTTPS://GRAFANA.homelab.net/d/1', rules)).toBe(
      'https://grafana.homelab.net/d/1',
    );
    expect(safeRedirectTarget('https://app.example.com/a b', rules)).toBe('/');
  });
  it('falls back instead of returning header-unsafe input', () => {
    expect(safeRedirectTarget('https://app.example.com/\r\nSet-Cookie: a=b', rules)).toBe('/');
  });

  it('falls back for unsafe or non-string input', () => {
    expect(safeRedirectTarget('https://evil.com', rules)).toBe('/');
    expect(safeRedirectTarget(undefined, rules)).toBe('/');
    expect(safeRedirectTarget(['/a'], rules)).toBe('/');
    expect(safeRedirectTarget('/ok', rules)).toBe('/ok');
  });
});
