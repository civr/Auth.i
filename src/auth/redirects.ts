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

export function isSafeRedirect(target: string, rules: RedirectRules): boolean {
  if (target.startsWith('/')) {
    return (
      !target.startsWith('//') &&
      !UNSAFE_RELATIVE.test(target) &&
      !ENCODED_UNSAFE_LEADING.test(target)
    );
  }
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (host === new URL(rules.issuerUrl).hostname.toLowerCase()) return true;
  if (rules.allowedHosts?.some((h) => h.toLowerCase() === host)) return true;
  if (rules.cookieDomain) {
    const domain = rules.cookieDomain.replace(/^\./, '').toLowerCase();
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

export function safeRedirectTarget(target: unknown, rules: RedirectRules, fallback = '/'): string {
  return typeof target === 'string' && isSafeRedirect(target, rules) ? target : fallback;
}
