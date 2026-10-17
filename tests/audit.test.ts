import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit/audit.js';
import { createTestDb, type TestDb } from './helpers/db.js';

let t: TestDb;
let audit: AuditLog;
beforeEach(async () => {
  t = await createTestDb();
  audit = new AuditLog(t.db);
});
afterEach(() => t.destroy());

describe('AuditLog', () => {
  it('records entries and lists newest first', async () => {
    await audit.record({ actor: { type: 'system' }, action: 'first' });
    await audit.record({
      actor: { type: 'user', id: 'u1' },
      action: 'second',
      target: 'thing',
      details: { a: 1 },
      ip: '10.0.0.1',
    });
    const entries = await audit.list();
    expect(entries.map((e) => e.action)).toEqual(['second', 'first']);
    expect(entries[0]).toMatchObject({
      actorType: 'user',
      actorId: 'u1',
      target: 'thing',
      details: { a: 1 },
      ip: '10.0.0.1',
    });
    expect(entries[1]).toMatchObject({ actorType: 'system', actorId: null, details: {} });
  });

  it('paginates with before and limit', async () => {
    for (const action of ['a', 'b', 'c']) await audit.record({ actor: { type: 'system' }, action });
    const [newest] = await audit.list({ limit: 1 });
    expect(newest!.action).toBe('c');
    const older = await audit.list({ before: newest!.id });
    expect(older.map((e) => e.action)).toEqual(['b', 'a']);
  });
});
