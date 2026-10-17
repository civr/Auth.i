import { describe, expect, it } from 'vitest';
import { parseTrustProxy } from '../src/http/app.js';

describe('parseTrustProxy', () => {
  it('maps true/false to booleans and lists to arrays', () => {
    expect(parseTrustProxy('true')).toBe(true);
    expect(parseTrustProxy('FALSE')).toBe(false);
    expect(parseTrustProxy('loopback, 10.0.0.0/8')).toEqual(['loopback', '10.0.0.0/8']);
  });
});
