import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import { passwordSchema, usernameSchema } from '../api/common.js';
import type { LoginRateLimiter } from '../auth/rate-limit.js';
import { hashToken } from '../crypto/secrets.js';
import type { User } from '../identity/users.js';
import type { Services } from '../services.js';
import type { SettingKey } from '../settings/keys.js';
import { SettingsValidationError } from '../settings/settings.js';

// Serialises setup against concurrent submissions (7_424_242–244 are taken by migrator, keys, bootstrap).
const LOCK_ID = 7_424_245;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export type SetupInput = {
  code: string;
  issuerUrl: string;
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
};

export type SetupResult =
  | { ok: true; user: User; changed: SettingKey[] }
  | { ok: false; reason: 'rate_limited' | 'bad_code' | 'already_complete' }
  | { ok: false; reason: 'invalid'; fieldErrors: Record<string, string> };

const normaliseCode = (code: string) => code.toUpperCase().replace(/[^A-Z0-9]/g, '');

export class SetupService {
  #codeHash: string | undefined;
  #complete = false;

  constructor(
    private readonly s: Pick<Services, 'db' | 'users' | 'settings' | 'audit'>,
    private readonly limiter: LoginRateLimiter,
  ) {}

  async isRequired(): Promise<boolean> {
    if (this.#complete) return false;
    if ((await this.s.users.count()) > 0) {
      this.#complete = true;
      this.#codeHash = undefined;
      return false;
    }
    return true;
  }

  issueCode(): string {
    const bytes = randomBytes(16);
    const raw = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
    this.#codeHash = hashToken(raw);
    return raw.match(/.{4}/g)!.join('-');
  }

  #codeMatches(code: string): boolean {
    if (!this.#codeHash) return false;
    const given = Buffer.from(hashToken(normaliseCode(code)), 'hex');
    const expected = Buffer.from(this.#codeHash, 'hex');
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  #validate(input: SetupInput): { errors: Record<string, string>; issuerUrl?: string } {
    const errors: Record<string, string> = {};
    const username = usernameSchema.safeParse(input.username.trim());
    if (!username.success) errors.username = username.error.issues[0]!.message;
    if (!z.email().safeParse(input.email.trim()).success) errors.email = 'Enter a valid email address';
    const password = passwordSchema.safeParse(input.password);
    if (!password.success) errors.password = password.error.issues[0]!.message;
    else if (input.password !== input.passwordConfirm) errors.passwordConfirm = 'Passwords do not match';
    let issuerUrl: string | undefined;
    if (!this.s.settings.isLocked('issuerUrl')) {
      try {
        issuerUrl = this.s.settings.validate({ issuerUrl: input.issuerUrl }).issuerUrl;
      } catch (e) {
        if (e instanceof SettingsValidationError) errors.issuerUrl = e.fieldErrors.issuerUrl ?? 'Invalid URL';
        else throw e;
      }
    }
    return { errors, ...(issuerUrl ? { issuerUrl } : {}) };
  }

  async complete(input: SetupInput, ip: string): Promise<SetupResult> {
    if (!(await this.isRequired())) return { ok: false, reason: 'already_complete' };
    const reservation = await this.limiter.reserve(`setup:${ip}`, `setup:${ip}`);
    if (reservation.blocked) return { ok: false, reason: 'rate_limited' };
    if (!this.#codeMatches(input.code)) return { ok: false, reason: 'bad_code' };
    const { errors, issuerUrl } = this.#validate(input);
    if (Object.keys(errors).length > 0) {
      await this.limiter.release(reservation.ids);
      return { ok: false, reason: 'invalid', fieldErrors: errors };
    }
    const outcome = await this.s.db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
      if ((await this.s.users.count()) > 0) return null;
      const user = await this.s.users.create({
        username: input.username.trim(),
        email: input.email.trim(),
        password: input.password,
        isAdmin: true,
      });
      return user;
    });
    if (!outcome) {
      this.#complete = true;
      return { ok: false, reason: 'already_complete' };
    }
    this.#complete = true;
    this.#codeHash = undefined;
    await this.limiter.release(reservation.ids);
    const actor = { type: 'user', id: outcome.id } as const;
    // The admin already exists and /setup is closed: a failure saving the URL must not turn into a 500.
    // Swallow it so the admin is signed in and can fix the public URL in Settings.
    let changed: SettingKey[] = [];
    if (issuerUrl) {
      try {
        changed = await this.s.settings.update({ issuerUrl }, actor, ip);
      } catch {
        changed = [];
      }
    }
    await this.s.audit.record({ actor, action: 'setup.complete', target: outcome.id, ip });
    return { ok: true, user: outcome, changed };
  }
}
