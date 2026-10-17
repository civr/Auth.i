import type { Db } from '../db/db.js';

export type Actor = { type: 'user' | 'token'; id: string } | { type: 'system' } | { type: 'anonymous' };

export interface AuditEntry {
  id: string;
  at: Date;
  actorType: string;
  actorId: string | null;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
  ip: string | null;
}

export interface AuditRecordInput {
  actor: Actor;
  action: string;
  target?: string | null;
  details?: Record<string, unknown>;
  ip?: string | null;
}

export class AuditLog {
  constructor(private readonly db: Db) {}

  async record(input: AuditRecordInput): Promise<void> {
    await this.db
      .insertInto('audit_log')
      .values({
        actor_type: input.actor.type,
        actor_id: 'id' in input.actor ? input.actor.id : null,
        action: input.action,
        target: input.target ?? null,
        details: JSON.stringify(input.details ?? {}),
        ip: input.ip ?? null,
      })
      .execute();
  }

  async list(opts: { limit?: number; before?: string } = {}): Promise<AuditEntry[]> {
    let query = this.db
      .selectFrom('audit_log')
      .selectAll()
      .orderBy('id', 'desc')
      .limit(opts.limit ?? 100);
    if (opts.before) query = query.where('id', '<', opts.before);
    const rows = await query.execute();
    return rows.map((r) => ({
      id: r.id,
      at: r.at,
      actorType: r.actor_type,
      actorId: r.actor_id,
      action: r.action,
      target: r.target,
      details: r.details,
      ip: r.ip,
    }));
  }
}
