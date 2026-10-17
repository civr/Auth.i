import { describe, expect, it, vi } from 'vitest';
import { EventBus, type DomainEvent } from '../src/events/bus.js';

describe('EventBus', () => {
  it('delivers events to subscribers in order', async () => {
    const bus = new EventBus();
    const seen: string[] = [];
    bus.subscribe((e) => {
      seen.push(`a:${e.type}`);
    });
    bus.subscribe(async (e) => {
      seen.push(`b:${e.type}`);
    });
    await bus.publish({ type: 'user.created', userId: 'u1' });
    expect(seen).toEqual(['a:user.created', 'b:user.created']);
  });

  it('isolates failing handlers and reports them', async () => {
    const onError = vi.fn();
    const bus = new EventBus(onError);
    const seen: DomainEvent[] = [];
    bus.subscribe(() => {
      throw new Error('boom');
    });
    bus.subscribe((e) => {
      seen.push(e);
    });
    const event: DomainEvent = { type: 'group.created', groupId: 'g1' };
    await bus.publish(event);
    expect(seen).toEqual([event]);
    expect(onError).toHaveBeenCalledWith(expect.any(Error), event);
  });

  it('supports unsubscribe', async () => {
    const bus = new EventBus();
    const handler = vi.fn();
    const off = bus.subscribe(handler);
    off();
    await bus.publish({ type: 'user.deleted', userId: 'u1' });
    expect(handler).not.toHaveBeenCalled();
  });
});
