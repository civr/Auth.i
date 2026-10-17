import { describe, expect, it } from 'vitest';
import { escapeLike, isUuid } from '../src/util.js';

describe('util', () => {
  it('recognises uuids', () => {
    expect(isUuid('8d0f1d8e-4c55-4b5e-9a35-1f0b2c3d4e5f')).toBe(true);
    expect(isUuid('nope')).toBe(false);
    expect(isUuid("8d0f1d8e-4c55-4b5e-9a35-1f0b2c3d4e5f' OR 1=1")).toBe(false);
  });

  it('escapes LIKE wildcards', () => {
    expect(escapeLike('50%_off\\')).toBe('50\\%\\_off\\\\');
  });
});
