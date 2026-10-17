CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username        text NOT NULL,
  email           text,
  display_name    text NOT NULL DEFAULT '',
  given_name      text,
  family_name     text,
  is_active       boolean NOT NULL DEFAULT true,
  is_admin        boolean NOT NULL DEFAULT false,
  password_hash   text,
  totp_secret_enc text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));
CREATE UNIQUE INDEX users_email_key ON users (lower(email)) WHERE email IS NOT NULL;

CREATE TABLE groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  source_id   uuid,
  external_id text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_name_key ON groups (lower(name));

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE applications (
  id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug                       text NOT NULL UNIQUE,
  name                       text NOT NULL,
  oidc_enabled               boolean NOT NULL DEFAULT false,
  forward_auth_enabled       boolean NOT NULL DEFAULT false,
  client_id                  text NOT NULL UNIQUE,
  client_secret_enc          text NOT NULL,
  token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post')),
  redirect_uris              text[] NOT NULL DEFAULT '{}',
  post_logout_redirect_uris  text[] NOT NULL DEFAULT '{}',
  external_host              text,
  allowed_group_ids          uuid[] NOT NULL DEFAULT '{}',
  launch_url                 text,
  created_at                 timestamptz NOT NULL DEFAULT now(),
  updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX applications_external_host_key ON applications (lower(external_host)) WHERE external_host IS NOT NULL;

CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash   text NOT NULL UNIQUE,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  ip           text,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE oidc_payloads (
  id          text NOT NULL,
  type        text NOT NULL,
  payload     jsonb NOT NULL,
  grant_id    text,
  user_code   text,
  uid         text,
  expires_at  timestamptz,
  consumed_at timestamptz,
  PRIMARY KEY (type, id)
);
CREATE INDEX oidc_payloads_grant_idx ON oidc_payloads (grant_id);
CREATE INDEX oidc_payloads_uid_idx ON oidc_payloads (uid);
CREATE INDEX oidc_payloads_user_code_idx ON oidc_payloads (user_code);
CREATE INDEX oidc_payloads_expires_idx ON oidc_payloads (expires_at);

CREATE TABLE signing_keys (
  kid             text PRIMARY KEY,
  alg             text NOT NULL,
  private_jwk_enc text NOT NULL,
  status          text NOT NULL CHECK (status IN ('active', 'retired')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  retired_at      timestamptz
);

CREATE TABLE api_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  token_hash   text NOT NULL UNIQUE,
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at   timestamptz
);

CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor_type text NOT NULL,
  actor_id   text,
  action     text NOT NULL,
  target     text,
  details    jsonb NOT NULL DEFAULT '{}',
  ip         text
);
CREATE INDEX audit_log_at_idx ON audit_log (at);

CREATE TABLE login_attempts (
  id  bigserial PRIMARY KEY,
  key text NOT NULL,
  at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_key_at_idx ON login_attempts (key, at);
