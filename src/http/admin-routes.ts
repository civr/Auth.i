import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { LOG_LEVELS, SETTING_KEYS, type SettingKey } from '../settings/keys.js';
import { SettingsValidationError, type SettingsPatch } from '../settings/settings.js';
import { applySettingsChange, type Services } from '../services.js';
import type { User } from '../identity/users.js';
import { requireAdmin } from './admin-guard.js';
import { issueCsrfToken, verifyCsrfToken } from './csrf.js';
import { renderPage } from './views.js';

type Body = Partial<Record<SettingKey | 'csrf', unknown>>;

const HELP: Record<SettingKey, string> = {
  issuerUrl: 'The address people open, e.g. https://auth.example.com. Apps use <public URL>/oidc as issuer.',
  cookieDomain: 'Optional. A parent domain such as example.com lets one sign-in cover all its subdomains (forward auth).',
  trustProxy: 'Which proxies may set X-Forwarded-* headers: IPs, CIDR ranges, loopback, linklocal, uniquelocal, or true/false.',
  logLevel: 'How much Keystone writes to its log.',
};
const LABELS: Record<SettingKey, string> = {
  issuerUrl: 'Public URL',
  cookieDomain: 'Cookie domain',
  trustProxy: 'Trusted proxies',
  logLevel: 'Log level',
};

export function registerAdminRoutes(app: FastifyInstance, s: Services, opts: { onRestart?: () => void }): void {
  const render = (
    req: FastifyRequest,
    reply: FastifyReply,
    user: User,
    data: { values?: Partial<Record<SettingKey, string>>; errors?: Partial<Record<SettingKey, string>>; notices?: string[]; restart?: boolean },
  ) =>
    renderPage(reply, 'admin/settings', {
      title: 'Settings',
      user,
      active: 'settings',
      csrf: issueCsrfToken(req, reply, s.settings.current()),
      fields: s.settings.describe().map((f) => ({
        ...f,
        label: LABELS[f.key],
        help: HELP[f.key],
        value: data.values?.[f.key] ?? f.value,
        error: data.errors?.[f.key] ?? null,
      })),
      logLevels: LOG_LEVELS,
      notices: data.notices ?? [],
      restart: data.restart ?? false,
    });

  app.get('/admin', async (_req, reply) => reply.redirect('/admin/settings'));

  app.get<{ Querystring: Record<string, string | undefined> }>('/admin/settings', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    const q = req.query;
    const notices: string[] = [];
    if (q.saved === '1') notices.push(q.restart === '1' ? 'Saved — restart Keystone to apply trusted proxies.' : 'Saved.');
    if (q.issuer === '1') {
      notices.push(`Connected apps must update their issuer to ${s.settings.current().issuerUrl}/oidc.`);
    }
    if (q.cookie === '1') notices.push('Cookie domain changed: people may need to sign in again.');
    if (q.oidc === 'failed') notices.push('Saved, but the OIDC endpoint could not be reloaded — see the logs.');
    return render(req, reply, user, { notices, restart: q.restart === '1' });
  });

  app.post<{ Body: Body }>('/admin/settings', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    const body = req.body ?? {};
    if (!verifyCsrfToken(req, body.csrf)) {
      reply.code(403);
      return renderPage(reply, 'error', { title: 'Forbidden', message: 'The form expired. Reload the page and try again.' });
    }
    const patch: SettingsPatch = {};
    for (const key of SETTING_KEYS) {
      const v = body[key];
      if (typeof v === 'string') patch[key] = v;
    }
    let changed: SettingKey[];
    try {
      changed = await s.settings.update(patch, { type: 'user', id: user.id }, req.ip);
    } catch (err) {
      if (!(err instanceof SettingsValidationError)) throw err;
      reply.code(400);
      return render(req, reply, user, { values: patch, errors: err.fieldErrors });
    }
    const { oidcReloadFailed } = await applySettingsChange(s, changed);
    if (changed.includes('logLevel')) app.log.level = s.settings.current().logLevel;
    const q = new URLSearchParams({ saved: '1' });
    if (changed.includes('trustProxy')) q.set('restart', '1');
    if (changed.includes('issuerUrl')) q.set('issuer', '1');
    if (changed.includes('cookieDomain')) q.set('cookie', '1');
    if (oidcReloadFailed) q.set('oidc', 'failed');
    return reply.redirect(`/admin/settings?${q.toString()}`);
  });

  app.post<{ Body: Body }>('/admin/restart', async (req, reply) => {
    const user = await requireAdmin(req, reply, s);
    if (!user) return reply;
    if (!verifyCsrfToken(req, (req.body ?? {}).csrf)) {
      reply.code(403);
      return renderPage(reply, 'error', { title: 'Forbidden', message: 'The form expired. Reload the page and try again.' });
    }
    await s.audit.record({ actor: { type: 'user', id: user.id }, action: 'system.restart', ip: req.ip });
    if (opts.onRestart) reply.raw.once('finish', () => setImmediate(opts.onRestart!));
    return renderPage(reply, 'admin/restarting', {
      title: 'Restarting',
      user,
      active: 'settings',
      refresh: '6;url=/admin/settings',
      canRestart: Boolean(opts.onRestart),
    });
  });
}
