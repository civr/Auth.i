import { randomBytes } from 'node:crypto';
import { closeSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

const envSchema = z
  .object({
    KEYSTONE_ISSUER_URL: z.url({ protocol: /^https?$/ }).default('http://localhost:9000'),
    KEYSTONE_COOKIE_DOMAIN: z.string().min(1).optional(),
    KEYSTONE_SECRET_KEY: z.string().optional().refine((v) => v === undefined || Buffer.from(v, 'base64').length === 32, {
      message: 'must be 32 random bytes, base64-encoded (openssl rand -base64 32)',
    }),
    DATABASE_URL: z.string().min(1).optional(),
    KEYSTONE_BOOTSTRAP_ADMIN_USER: z.string().min(1).optional(),
    KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),
    KEYSTONE_BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
    KEYSTONE_TRUST_PROXY: z.string().default('loopback,linklocal,uniquelocal'),
    PORT: z.coerce.number().int().positive().default(9000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  })
  .superRefine((env, ctx) => {
    if (env.KEYSTONE_BOOTSTRAP_ADMIN_USER && !env.KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD) {
      ctx.addIssue({
        code: 'custom',
        path: ['KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD'],
        message: 'required when KEYSTONE_BOOTSTRAP_ADMIN_USER is set',
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

function loadOrCreateSecretKey(dataDir: string): Buffer {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const keyPath = path.join(dataDir, 'secret.key');

  try {
    const key = readFileSync(keyPath);
    if (key.length !== 32) throw new Error(`Invalid persisted Keystone secret key at ${keyPath}; expected 32 bytes.`);
    return key;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const key = randomBytes(32);
  let fileDescriptor: number;
  try {
    fileDescriptor = openSync(keyPath, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      const existingKey = readFileSync(keyPath);
      if (existingKey.length !== 32) throw new Error(`Invalid persisted Keystone secret key at ${keyPath}; expected 32 bytes.`);
      return existingKey;
    }
    throw error;
  }

  try {
    writeFileSync(fileDescriptor, key);
  } finally {
    closeSync(fileDescriptor);
  }
  return key;
}

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
  options: { dataDir?: string } = {},
): Config {
  const present = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== ''));
  const parsed = envSchema.safeParse(present);
  if (!parsed.success) {
    throw new Error(`Invalid configuration:\n${z.prettifyError(parsed.error)}`);
  }
  const e = parsed.data;
  const issuerUrl = e.KEYSTONE_ISSUER_URL.replace(/\/+$/, '');
  const dataDir = options.dataDir ?? (process.env.NODE_ENV === 'production' ? '/app/data' : path.resolve('.keystone'));
  const secretKey = e.KEYSTONE_SECRET_KEY
    ? Buffer.from(e.KEYSTONE_SECRET_KEY, 'base64')
    : loadOrCreateSecretKey(dataDir);
  let databaseUrl = e.DATABASE_URL;
  if (!databaseUrl) {
    const passwordPath = path.join(dataDir, 'postgres-password');
    let password: string | undefined;
    try {
      password = readFileSync(passwordPath, 'utf8').trim();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || process.env.NODE_ENV === 'production' || options.dataDir) {
        throw error;
      }
    }
    if (password) {
      databaseUrl = `postgres://keystone:${encodeURIComponent(password)}@postgres:5432/keystone`;
    } else if (process.env.NODE_ENV === 'production') {
      throw new Error(`Postgres password file is missing: ${passwordPath}`);
    } else {
      databaseUrl = 'postgres://keystone:keystone@localhost:5432/keystone';
    }
  }
  return {
    issuerUrl,
    cookieDomain: e.KEYSTONE_COOKIE_DOMAIN,
    secureCookies: issuerUrl.startsWith('https://'),
    secretKey,
    databaseUrl,
    bootstrapAdmin: e.KEYSTONE_BOOTSTRAP_ADMIN_USER
      ? {
          username: e.KEYSTONE_BOOTSTRAP_ADMIN_USER,
          password: e.KEYSTONE_BOOTSTRAP_ADMIN_PASSWORD!,
          ...(e.KEYSTONE_BOOTSTRAP_ADMIN_EMAIL ? { email: e.KEYSTONE_BOOTSTRAP_ADMIN_EMAIL } : {}),
        }
      : undefined,
    trustProxy: e.KEYSTONE_TRUST_PROXY,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
  };
}
