import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../src/crypto/passwords.js';
import { createSecretBox, deriveKey, hashToken, randomToken } from '../src/crypto/secrets.js';

const master = Buffer.alloc(32, 3);

describe('SecretBox', () => {
  const box = createSecretBox(master);

  it('round-trips text, including empty strings and unicode', () => {
    for (const plain of ['hunter2', '', 'zoë 🔐']) {
      expect(box.decrypt(box.encrypt(plain))).toBe(plain);
    }
  });

  it('produces a different ciphertext each time', () => {
    expect(box.encrypt('same')).not.toBe(box.encrypt('same'));
  });

  it('rejects tampered ciphertext', () => {
    const sealed = box.encrypt('secret');
    const parts = sealed.split('.');
    parts[2] = Buffer.from('tampered').toString('base64url');
    expect(() => box.decrypt(parts.join('.'))).toThrow();
  });

  it('rejects ciphertext from another key', () => {
    const other = createSecretBox(Buffer.alloc(32, 4));
    expect(() => other.decrypt(box.encrypt('secret'))).toThrow();
  });

  it('rejects malformed input', () => {
    expect(() => box.decrypt('nonsense')).toThrow(/Malformed/);
  });
});

describe('deriveKey', () => {
  it('derives distinct 32-byte keys per purpose', () => {
    const a = deriveKey(master, 'a');
    expect(a).toHaveLength(32);
    expect(a.equals(deriveKey(master, 'a'))).toBe(true);
    expect(a.equals(deriveKey(master, 'b'))).toBe(false);
  });
});

describe('tokens', () => {
  it('generates unique url-safe tokens', () => {
    const t = randomToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken()).not.toBe(t);
  });

  it('hashes tokens deterministically to hex', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('passwords', () => {
  it('hashes with argon2id and verifies', async () => {
    const hash = await hashPassword('correct-horse-battery');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'correct-horse-battery')).toBe(true);
    expect(await verifyPassword(hash, 'wrong-password-123')).toBe(false);
  });

  it('returns false for a missing hash', async () => {
    expect(await verifyPassword(null, 'anything')).toBe(false);
  });

  it('returns false for a garbage hash instead of throwing', async () => {
    expect(await verifyPassword('not-a-hash', 'anything')).toBe(false);
  });
});
