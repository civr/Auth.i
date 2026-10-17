export interface RedirectRules {
  issuerUrl: string;
  cookieDomain?: string;
  allowedHosts?: readonly string[];
}

// Backslashes and control characters are normalised away by browsers ("/\evil" → "//evil").
const UNSAFE_RELATIVE = /[\\\u0000-\u001f\u007f]/;
// Percent-encoded control characters, backslash or slash directly after the leading "/"
// (e.g. "/%09/evil.com", "/%2F%2Fevil.com"). Not decoded by browsers today, but rejected
// defensively so a relative target can never be reinterpreted as a protocol-relative one.
const ENCODED_UNSAFE_LEADING = /^\/%(?:0[0-9a-f]|1[0-9a-f]|7f|2f|5c)/i;
// Any control character or whitespace in an absolute URL is rejected before parsing,
// so the string we check is the string we return (and cannot inject headers).
const ABSOLUTE_CONTROL_OR_SPACE = /[\u0000- \u007f]/;
const ABSOLUTE_PREFIX = /^https?:\/\//i;

function normalisedDomain(cookieDomain: string | undefined): string | undefined {
  if (!cookieDomain) return undefined;
  const domain = cookieDomain.replace(/^\.+/, '').toLowerCase();
  if (domain === '' || domain.split('.').some((label) => label === '')) return undefined;
  return domain;
}

// Returns the value that is safe to redirect to (canonical href for absolute URLs), or null.
function normaliseRedirect(target: string, rules: RedirectRules): string | null {
  if (target.startsWith('/')) {
    if (target.startsWith('//')) return null;
    if (UNSAFE_RELATIVE.test(target) || ENCODED_UNSAFE_LEADING.test(target)) return null;
    return target;
  }
  if (ABSOLUTE_CONTROL_OR_SPACE.test(target)) return null;
  if (!ABSOLUTE_PREFIX.test(target)) return null;
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  const host = url.hostname.toLowerCase();
  if (host === new URL(rules.issuerUrl).hostname.toLowerCase()) return url.href;
  if (rules.allowedHosts?.some((h) => h.toLowerCase() === host)) return url.href;
  const domain = normalisedDomain(rules.cookieDomain);
  if (domain && (host === domain || host.endsWith(`.${domain}`))) return url.href;
  return null;
}

export function isSafeRedirect(target: string, rules: RedirectRules): boolean {
  return normaliseRedirect(target, rules) !== null;
}

export function safeRedirectTarget(target: unknown, rules: RedirectRules, fallback = '/'): string {
  if (typeof target !== 'string') return fallback;
  return normaliseRedirect(target, rules) ?? fallback;
}
