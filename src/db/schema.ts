import type { ColumnType, Generated } from 'kysely';

/** jsonb columns: read as objects, always written as JSON strings. */
type Json<T = Record<string, unknown>> = ColumnType<T, string, string>;

export interface UsersTable {
  id: Generated<string>;
  username: string;
  email: string | null;
  display_name: Generated<string>;
  given_name: string | null;
  family_name: string | null;
  is_active: Generated<boolean>;
  is_admin: Generated<boolean>;
  password_hash: string | null;
  totp_secret_enc: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface GroupsTable {
  id: Generated<string>;
  name: string;
  description: Generated<string>;
  source_id: string | null;
  external_id: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface GroupMembersTable {
  group_id: string;
  user_id: string;
}

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post';

export interface ApplicationsTable {
  id: Generated<string>;
  slug: string;
  name: string;
  oidc_enabled: Generated<boolean>;
  forward_auth_enabled: Generated<boolean>;
  client_id: string;
  client_secret_enc: string;
  token_endpoint_auth_method: Generated<TokenEndpointAuthMethod>;
  redirect_uris: Generated<string[]>;
  post_logout_redirect_uris: Generated<string[]>;
  external_host: string | null;
  allowed_group_ids: Generated<string[]>;
  launch_url: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface SessionsTable {
  id: Generated<string>;
  token_hash: string;
  user_id: string;
  created_at: Generated<Date>;
  expires_at: Date;
  last_seen_at: Generated<Date>;
  ip: string | null;
  user_agent: string | null;
}

export interface OidcPayloadsTable {
  id: string;
  type: string;
  payload: Json;
  grant_id: string | null;
  user_code: string | null;
  uid: string | null;
  expires_at: Date | null;
  consumed_at: Date | null;
}

export interface SigningKeysTable {
  kid: string;
  alg: string;
  private_jwk_enc: string;
  status: 'active' | 'retired';
  created_at: Generated<Date>;
  retired_at: Date | null;
}

export interface ApiTokensTable {
  id: Generated<string>;
  name: string;
  token_hash: string;
  created_by: string | null;
  created_at: Generated<Date>;
  last_used_at: Date | null;
  expires_at: Date | null;
}

export interface AuditLogTable {
  id: Generated<string>;
  at: Generated<Date>;
  actor_type: string;
  actor_id: string | null;
  action: string;
  target: string | null;
  details: ColumnType<Record<string, unknown>, string | undefined, string>;
  ip: string | null;
}

export interface LoginAttemptsTable {
  id: Generated<string>;
  key: string;
  at: Generated<Date>;
}

export interface SettingsTable {
  key: string;
  value: ColumnType<unknown, string, string>;
  updated_at: ColumnType<Date, Date | undefined, Date>;
  updated_by: string | null;
}

export interface SchemaMigrationsTable {
  name: string;
  applied_at: Generated<Date>;
}

export interface Database {
  users: UsersTable;
  groups: GroupsTable;
  group_members: GroupMembersTable;
  applications: ApplicationsTable;
  sessions: SessionsTable;
  oidc_payloads: OidcPayloadsTable;
  signing_keys: SigningKeysTable;
  api_tokens: ApiTokensTable;
  audit_log: AuditLogTable;
  login_attempts: LoginAttemptsTable;
  settings: SettingsTable;
  schema_migrations: SchemaMigrationsTable;
}
