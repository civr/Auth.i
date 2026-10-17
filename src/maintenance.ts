import { purgeExpiredOidcPayloads } from './oidc/adapter.js';
import type { Services } from './services.js';

type MaintenanceDeps = Pick<Services, 'sessions' | 'limiter' | 'db'>;

export async function runMaintenanceOnce(s: MaintenanceDeps): Promise<void> {
  await s.sessions.purgeExpired();
  await s.limiter.purge();
  await purgeExpiredOidcPayloads(s.db);
}

export function startMaintenance(
  s: MaintenanceDeps,
  onError: (err: unknown) => void,
  intervalMs = 10 * 60 * 1000,
): () => void {
  const timer = setInterval(() => {
    runMaintenanceOnce(s).catch(onError);
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
