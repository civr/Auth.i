export type DomainEvent =
  | { type: 'user.created' | 'user.updated' | 'user.deactivated' | 'user.deleted'; userId: string }
  | { type: 'group.created' | 'group.updated'; groupId: string }
  | { type: 'group.deleted'; groupId: string; name: string }
  | { type: 'group.members_changed'; groupId: string; userIds: string[] };

export type EventHandler = (event: DomainEvent) => void | Promise<void>;

export class EventBus {
  readonly #handlers = new Set<EventHandler>();

  constructor(private readonly onError: (err: unknown, event: DomainEvent) => void = () => {}) {}

  subscribe(handler: EventHandler): () => void {
    this.#handlers.add(handler);
    return () => this.#handlers.delete(handler);
  }

  async publish(event: DomainEvent): Promise<void> {
    for (const handler of this.#handlers) {
      try {
        await handler(event);
      } catch (err) {
        this.onError(err, event);
      }
    }
  }
}
