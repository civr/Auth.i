import { z } from 'zod';
import { passwordSchema, usernameSchema } from '../api/common.js';
import { randomToken } from '../crypto/secrets.js';
import { revokeOidcForAccount } from '../oidc/adapter.js';
import type { Services } from '../services.js';

export const USAGE = `Usage: keystone <command>

Commands:
  create-api-token <name>            Create an admin API token (shown once)
  create-admin <username> [email]    Create an admin user with a generated password
  reset-password <username-or-email> Generate a new password and end the user's sessions`;

function check<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new Error(`Invalid ${label}: ${result.error.issues[0]?.message}`);
  return result.data;
}

function generatePassword(): string {
  return check(passwordSchema, randomToken(18), 'password');
}

export async function runCommand(s: Services, argv: string[]): Promise<string> {
  const [command, ...args] = argv;
  switch (command) {
    case 'create-api-token': {
      const name = args[0];
      if (!name) throw new Error('Usage: create-api-token <name>');
      const { token, apiToken } = await s.apiTokens.create({ name });
      await s.audit.record({ actor: { type: 'system' }, action: 'api_token.create', target: apiToken.id, details: { name, via: 'cli' } });
      return `API token "${name}" created. It is shown only once:\n${token}`;
    }
    case 'create-admin': {
      const [rawUsername, rawEmail] = args;
      if (!rawUsername) throw new Error('Usage: create-admin <username> [email]');
      const username = check(usernameSchema, rawUsername, 'username');
      const email = rawEmail === undefined ? null : check(z.email(), rawEmail, 'email');
      const password = generatePassword();
      const user = await s.users.create({ username, email, password, isAdmin: true });
      await s.audit.record({ actor: { type: 'system' }, action: 'user.create', target: user.id, details: { via: 'cli' } });
      return `Admin "${username}" created.\nPassword: ${password}`;
    }
    case 'reset-password': {
      const identifier = args[0];
      if (!identifier) throw new Error('Usage: reset-password <username-or-email>');
      const found = await s.users.findByLogin(identifier);
      if (!found) throw new Error(`User "${identifier}" not found`);
      const password = generatePassword();
      await s.users.setPassword(found.user.id, password);
      await s.sessions.destroyAllForUser(found.user.id);
      await revokeOidcForAccount(s.db, found.user.id);
      await s.limiter.clear(found.user.username);
      if (found.user.email) await s.limiter.clear(found.user.email);
      await s.audit.record({ actor: { type: 'system' }, action: 'user.password_set', target: found.user.id, details: { via: 'cli' } });
      return `Password for "${found.user.username}" reset.\nPassword: ${password}`;
    }
    default:
      return USAGE;
  }
}
