import { z } from 'zod';

const envSchema = z
  .object({
    AUTHI_ISSUER_URL: z.url({ protocol: /^https?$/ }),
    AUTHI_COOKIE_DOMAIN: z.string().min(1).optional(),
    AUTHI_SECRET_KEY: z.string().refine((v) => Buffer.from(v, 'base64').length === 32, {
      message: 'must be 32 random bytes, base64-encoded (openssl rand -base64 32)',
    }),
    DATABASE_URL: z.string().min(1),
    AUTHI_BOOTSTRAP_ADMIN_USER: z.string().min(1).optional(),
    AUTHI_BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),
    AUTHI_BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
    AUTHI_TRUST_PROXY: z.string().default('loopback,linklocal,uniquelocal'),
    PORT: z.coerce.number().int().positive().default(9000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  })
  .superRefine((env, ctx) => {
    if (env.AUTHI_BOOTSTRAP_ADMIN_USER && !env.AUTHI_BOOTSTRAP_ADMIN_PASSWORD) {
      ctx.addIssue({
        code: 'custom',
        path: ['AUTHI_BOOTSTRAP_ADMIN_PASSWORD'],
        message: 'required when AUTHI_BOOTSTRAP_ADMIN_USER is set',
      });
    }
  });

export interface Config {
  issuerUrl: string;
  cookieDomain: string | undefined;
  secureCookies: boolean;
  secretKey: Buffer;
  databaseUrl: string;
  bootstrapAdmin: { username: string; password: string; email?: string } | undefined;
  trustProxy: string;
  port: number;
  logLevel: string;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const present = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== ''));
  const parsed = envSchema.safeParse(present);
  if (!parsed.success) {
    throw new Error(`Invalid configuration:\n${z.prettifyError(parsed.error)}`);
  }
  const e = parsed.data;
  const issuerUrl = e.AUTHI_ISSUER_URL.replace(/\/+$/, '');
  return {
    issuerUrl,
    cookieDomain: e.AUTHI_COOKIE_DOMAIN,
    secureCookies: issuerUrl.startsWith('https://'),
    secretKey: Buffer.from(e.AUTHI_SECRET_KEY, 'base64'),
    databaseUrl: e.DATABASE_URL,
    bootstrapAdmin: e.AUTHI_BOOTSTRAP_ADMIN_USER
      ? {
          username: e.AUTHI_BOOTSTRAP_ADMIN_USER,
          password: e.AUTHI_BOOTSTRAP_ADMIN_PASSWORD!,
          ...(e.AUTHI_BOOTSTRAP_ADMIN_EMAIL ? { email: e.AUTHI_BOOTSTRAP_ADMIN_EMAIL } : {}),
        }
      : undefined,
    trustProxy: e.AUTHI_TRUST_PROXY,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
  };
}
