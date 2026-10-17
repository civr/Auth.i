import * as argon2 from 'argon2';

// OWASP baseline for argon2id: m=19 MiB, t=2, p=1.
const OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

let dummyHash: Promise<string> | undefined;

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, OPTIONS);
}

export async function verifyPassword(hash: string | null, password: string): Promise<boolean> {
  if (hash === null) {
    // Spend the same work as a real check so unknown usernames are not distinguishable by timing.
    dummyHash ??= argon2.hash('keystone-dummy-password', OPTIONS);
    await argon2.verify(await dummyHash, password);
    return false;
  }
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
