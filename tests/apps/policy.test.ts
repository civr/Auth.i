import { describe, expect, it } from 'vitest';
import { canAccess } from '../../src/apps/policy.js';

describe('canAccess', () => {
  const active = { isActive: true };
  it('allows every active user when the app has no group restriction', () => {
    expect(canAccess(active, [], { allowedGroupIds: [] })).toBe(true);
  });
  it('requires membership of any allowed group', () => {
    const app = { allowedGroupIds: ['g1', 'g2'] };
    expect(canAccess(active, ['g2'], app)).toBe(true);
    expect(canAccess(active, ['g3'], app)).toBe(false);
    expect(canAccess(active, [], app)).toBe(false);
  });
  it('never allows inactive users', () => {
    expect(canAccess({ isActive: false }, ['g1'], { allowedGroupIds: [] })).toBe(false);
  });
});
