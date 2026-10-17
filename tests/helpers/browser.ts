export interface Page {
  url: URL;
  response: Response | null;
}

const decodeHtml = (s: string) =>
  s.replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

/** Minimal cookie-keeping browser for one host. Ignores cookie domain/path, which is fine for tests on 127.0.0.1. */
export class TestBrowser {
  readonly jar = new Map<string, string>();

  async fetch(url: string, init: { form?: Record<string, string> } = {}): Promise<Response> {
    const headers: Record<string, string> = {};
    if (this.jar.size) headers.cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    let body: string | undefined;
    if (init.form) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(init.form).toString();
    }
    const res = await fetch(url, { method: init.form ? 'POST' : 'GET', headers, body, redirect: 'manual' });
    for (const raw of res.headers.getSetCookie()) {
      const [pair = '', ...attrs] = raw.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
      if (expired || value === '') this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }

  /** Follows redirects until `stop` matches the next URL or a non-redirect response arrives. */
  async navigate(url: string, stop: (u: URL) => boolean = () => false): Promise<Page> {
    let current = new URL(url);
    for (let hop = 0; hop < 20; hop++) {
      if (stop(current)) return { url: current, response: null };
      const res = await this.fetch(current.href);
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location) {
        current = new URL(location, current);
        continue;
      }
      return { url: current, response: res };
    }
    throw new Error('Too many redirects');
  }

  /** Submits the Keystone login form shown on `page` and follows the resulting redirects. */
  async signIn(page: Page, identifier: string, password: string, stop: (u: URL) => boolean = () => false): Promise<Page> {
    const html = await page.response!.text();
    const field = (name: string) => decodeHtml(html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? '');
    const res = await this.fetch(new URL('/login', page.url).href, {
      form: { csrf: field('csrf'), rd: field('rd'), identifier, password },
    });
    const location = res.headers.get('location');
    if (!location) return { url: page.url, response: res };
    return this.navigate(new URL(location, page.url).href, stop);
  }
}
