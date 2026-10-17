import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApplicationService } from '../../src/apps/applications.js';
import { createSecretBox } from '../../src/crypto/secrets.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/errors.js';
import { EventBus } from '../../src/events/bus.js';
import { GroupService } from '../../src/identity/groups.js';
import { createTestDb, type TestDb } from '../helpers/db.js';

let t: TestDb;
let apps: ApplicationService;
let groups: GroupService;

beforeEach(async () => {
  t = await createTestDb();
  groups = new GroupService(t.db, new EventBus());
  apps = new ApplicationService(t.db, createSecretBox(Buffer.alloc(32, 9), 'client-secrets'), groups);
});
afterEach(() => t.destroy());

const oidcApp = {
  slug: 'demo',
  name: 'Demo',
  oidcEnabled: true,
  redirectUris: ['https://demo.example.com/callback'],
};

describe('ApplicationService', () => {
  it('creates an app whose client_id is the slug and returns the secret once', async () => {
    const { application, clientSecret } = await apps.create(oidcApp);
    expect(application).toMatchObject({
      slug: 'demo',
      clientId: 'demo',
      oidcEnabled: true,
      forwardAuthEnabled: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      allowedGroupIds: [],
    });
    expect(clientSecret.length).toBeGreaterThanOrEqual(43);
    expect(application).not.toHaveProperty('clientSecret');
    const raw = await t.db.selectFrom('applications').select('client_secret_enc').executeTakeFirstOrThrow();
    expect(raw.client_secret_enc).not.toContain(clientSecret);
  });

  it('serves OIDC client metadata with the decrypted secret, only when OIDC is enabled', async () => {
    const { clientSecret } = await apps.create(oidcApp);
    expect(await apps.oidcClientMetadata('demo')).toEqual({
      client_id: 'demo',
      client_secret: clientSecret,
      client_name: 'Demo',
      redirect_uris: ['https://demo.example.com/callback'],
      post_logout_redirect_uris: [],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    });
    await apps.create({ slug: 'proxy-only', name: 'Proxy', forwardAuthEnabled: true, externalHost: 'p.example.com' });
    expect(await apps.oidcClientMetadata('proxy-only')).toBeUndefined();
    expect(await apps.oidcClientMetadata('unknown')).toBeUndefined();
  });

  it('enforces consistency rules', async () => {
    await expect(apps.create({ slug: 'a1', name: 'A', oidcEnabled: true })).rejects.toBeInstanceOf(ValidationError);
    await expect(apps.create({ slug: 'a2', name: 'A', forwardAuthEnabled: true })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(
      apps.create({ ...oidcApp, slug: 'a3', allowedGroupIds: ['00000000-0000-0000-0000-000000000000'] }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('rejects duplicate slugs and external hosts', async () => {
    await apps.create({ ...oidcApp, forwardAuthEnabled: true, externalHost: 'demo.example.com' });
    await expect(apps.create(oidcApp)).rejects.toBeInstanceOf(ConflictError);
    await expect(
      apps.create({ slug: 'other', name: 'O', forwardAuthEnabled: true, externalHost: 'DEMO.example.com' }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('finds forward-auth apps by host, case-insensitively, and lists their hosts', async () => {
    await apps.create({ slug: 'proxy', name: 'Proxy', forwardAuthEnabled: true, externalHost: 'Proxy.Example.com' });
    await apps.create(oidcApp);
    expect((await apps.getByExternalHost('proxy.example.COM'))?.slug).toBe('proxy');
    expect(await apps.getByExternalHost('nope.example.com')).toBeNull();
    expect(await apps.forwardAuthHosts()).toEqual(['proxy.example.com']);
  });

  it('updates apps and validates the merged result', async () => {
    const g = await groups.create({ name: 'staff' });
    const { application } = await apps.create(oidcApp);
    const updated = await apps.update(application.id, { name: 'Demo 2', allowedGroupIds: [g.id] });
    expect(updated).toMatchObject({ name: 'Demo 2', allowedGroupIds: [g.id] });
    await expect(apps.update(application.id, { redirectUris: [] })).rejects.toBeInstanceOf(ValidationError);
    await expect(apps.update('00000000-0000-0000-0000-000000000000', { name: 'x' })).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('rotates the secret', async () => {
    const { application, clientSecret } = await apps.create(oidcApp);
    const next = await apps.rotateSecret(application.id);
    expect(next).not.toBe(clientSecret);
    expect((await apps.oidcClientMetadata('demo'))?.client_secret).toBe(next);
  });

  it('deletes apps', async () => {
    const { application } = await apps.create(oidcApp);
    await apps.delete(application.id);
    expect(await apps.get(application.id)).toBeNull();
    await expect(apps.delete(application.id)).rejects.toBeInstanceOf(NotFoundError);
  });
});
