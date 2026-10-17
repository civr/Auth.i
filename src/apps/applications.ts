import type { Selectable } from 'kysely';
import { randomToken, type SecretBox } from '../crypto/secrets.js';
import type { Db } from '../db/db.js';
import type { ApplicationsTable, TokenEndpointAuthMethod } from '../db/schema.js';
import { ConflictError, NotFoundError, ValidationError, isUniqueViolation } from '../errors.js';
import type { GroupService } from '../identity/groups.js';
import { isUuid } from '../util.js';

export interface Application {
  id: string;
  slug: string;
  name: string;
  oidcEnabled: boolean;
  forwardAuthEnabled: boolean;
  clientId: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  externalHost: string | null;
  allowedGroupIds: string[];
  launchUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateApplicationInput {
  slug: string;
  name: string;
  oidcEnabled?: boolean;
  forwardAuthEnabled?: boolean;
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  externalHost?: string | null;
  allowedGroupIds?: string[];
  launchUrl?: string | null;
}

export type UpdateApplicationInput = Partial<Omit<CreateApplicationInput, 'slug'>>;

// A type alias (not an interface) so it stays assignable to oidc-provider's AdapterPayload index signature.
export type OidcClientMetadata = {
  client_id: string;
  client_secret: string;
  client_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: ('authorization_code' | 'refresh_token')[];
  response_types: 'code'[];
  token_endpoint_auth_method: TokenEndpointAuthMethod;
};

type Row = Selectable<ApplicationsTable>;

function toApplication(row: Row): Application {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    oidcEnabled: row.oidc_enabled,
    forwardAuthEnabled: row.forward_auth_enabled,
    clientId: row.client_id,
    tokenEndpointAuthMethod: row.token_endpoint_auth_method,
    redirectUris: row.redirect_uris,
    postLogoutRedirectUris: row.post_logout_redirect_uris,
    externalHost: row.external_host,
    allowedGroupIds: row.allowed_group_ids,
    launchUrl: row.launch_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const CONFLICT_MESSAGE = 'An application with this slug or external host already exists';

export class ApplicationService {
  constructor(
    private readonly db: Db,
    private readonly box: SecretBox,
    private readonly groups: GroupService,
  ) {}

  private async assertConsistent(app: {
    oidcEnabled: boolean;
    forwardAuthEnabled: boolean;
    redirectUris: string[];
    externalHost: string | null;
    allowedGroupIds: string[];
  }): Promise<void> {
    if (app.oidcEnabled && app.redirectUris.length === 0) {
      throw new ValidationError('OIDC applications need at least one redirect URI');
    }
    if (app.forwardAuthEnabled && !app.externalHost) {
      throw new ValidationError('Forward-auth applications need an external host');
    }
    const unique = [...new Set(app.allowedGroupIds)];
    if ((await this.groups.countExisting(unique)) !== unique.length) {
      throw new ValidationError('allowedGroupIds contains unknown groups');
    }
  }

  async create(input: CreateApplicationInput): Promise<{ application: Application; clientSecret: string }> {
    const values = {
      oidcEnabled: input.oidcEnabled ?? false,
      forwardAuthEnabled: input.forwardAuthEnabled ?? false,
      redirectUris: input.redirectUris ?? [],
      externalHost: input.externalHost?.toLowerCase() ?? null,
      allowedGroupIds: [...new Set(input.allowedGroupIds ?? [])],
    };
    await this.assertConsistent(values);
    const clientSecret = randomToken(32);
    try {
      const row = await this.db
        .insertInto('applications')
        .values({
          slug: input.slug,
          name: input.name,
          oidc_enabled: values.oidcEnabled,
          forward_auth_enabled: values.forwardAuthEnabled,
          client_id: input.slug,
          client_secret_enc: this.box.encrypt(clientSecret),
          token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? 'client_secret_basic',
          redirect_uris: values.redirectUris,
          post_logout_redirect_uris: input.postLogoutRedirectUris ?? [],
          external_host: values.externalHost,
          allowed_group_ids: values.allowedGroupIds,
          launch_url: input.launchUrl ?? null,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
      return { application: toApplication(row), clientSecret };
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
  }

  async get(id: string): Promise<Application | null> {
    if (!isUuid(id)) return null;
    const row = await this.db.selectFrom('applications').selectAll().where('id', '=', id).executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async getByClientId(clientId: string): Promise<Application | null> {
    const row = await this.db.selectFrom('applications').selectAll().where('client_id', '=', clientId).executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async getByExternalHost(host: string): Promise<Application | null> {
    const row = await this.db
      .selectFrom('applications')
      .selectAll()
      .where((eb) => eb(eb.fn('lower', ['external_host']), '=', host.toLowerCase()))
      .executeTakeFirst();
    return row ? toApplication(row) : null;
  }

  async list(): Promise<Application[]> {
    return (await this.db.selectFrom('applications').selectAll().orderBy('name').execute()).map(toApplication);
  }

  async update(id: string, input: UpdateApplicationInput): Promise<Application> {
    const existing = await this.get(id);
    if (!existing) throw new NotFoundError('Application not found');
    const merged = {
      oidcEnabled: input.oidcEnabled ?? existing.oidcEnabled,
      forwardAuthEnabled: input.forwardAuthEnabled ?? existing.forwardAuthEnabled,
      redirectUris: input.redirectUris ?? existing.redirectUris,
      externalHost: input.externalHost === undefined ? existing.externalHost : (input.externalHost?.toLowerCase() ?? null),
      allowedGroupIds: input.allowedGroupIds ? [...new Set(input.allowedGroupIds)] : existing.allowedGroupIds,
    };
    await this.assertConsistent(merged);
    try {
      const row = await this.db
        .updateTable('applications')
        .set({
          name: input.name ?? existing.name,
          oidc_enabled: merged.oidcEnabled,
          forward_auth_enabled: merged.forwardAuthEnabled,
          token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod,
          redirect_uris: merged.redirectUris,
          post_logout_redirect_uris: input.postLogoutRedirectUris ?? existing.postLogoutRedirectUris,
          external_host: merged.externalHost,
          allowed_group_ids: merged.allowedGroupIds,
          launch_url: input.launchUrl === undefined ? existing.launchUrl : input.launchUrl,
          updated_at: new Date(),
        })
        .where('id', '=', id)
        .returningAll()
        .executeTakeFirstOrThrow();
      return toApplication(row);
    } catch (err) {
      if (isUniqueViolation(err)) throw new ConflictError(CONFLICT_MESSAGE);
      throw err;
    }
  }

  async delete(id: string): Promise<void> {
    const row = isUuid(id)
      ? await this.db.deleteFrom('applications').where('id', '=', id).returning('id').executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('Application not found');
  }

  async rotateSecret(id: string): Promise<string> {
    const clientSecret = randomToken(32);
    const row = isUuid(id)
      ? await this.db
          .updateTable('applications')
          .set({ client_secret_enc: this.box.encrypt(clientSecret), updated_at: new Date() })
          .where('id', '=', id)
          .returning('id')
          .executeTakeFirst()
      : undefined;
    if (!row) throw new NotFoundError('Application not found');
    return clientSecret;
  }

  async forwardAuthHosts(): Promise<string[]> {
    const rows = await this.db
      .selectFrom('applications')
      .select('external_host')
      .where('forward_auth_enabled', '=', true)
      .where('external_host', 'is not', null)
      .orderBy('external_host')
      .execute();
    return rows.map((r) => r.external_host!);
  }

  async oidcClientMetadata(clientId: string): Promise<OidcClientMetadata | undefined> {
    const row = await this.db
      .selectFrom('applications')
      .selectAll()
      .where('client_id', '=', clientId)
      .where('oidc_enabled', '=', true)
      .executeTakeFirst();
    if (!row) return undefined;
    return {
      client_id: row.client_id,
      client_secret: this.box.decrypt(row.client_secret_enc),
      client_name: row.name,
      redirect_uris: row.redirect_uris,
      post_logout_redirect_uris: row.post_logout_redirect_uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: row.token_endpoint_auth_method,
    };
  }
}
