-- BeeCD Database Schema (Multi-Tenant)
-- Single initialization script - creates everything correctly from the start

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Tenants (must be created first - other tables reference it)
-- ============================================================================

CREATE TABLE "tenants" (
  "id" uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  "domain" text NOT NULL UNIQUE,
  "name" text NOT NULL,
  "status" text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  "config" jsonb DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz
);

CREATE INDEX "idx_tenants_domain" ON "tenants" ("domain") WHERE "deleted_at" IS NULL;
CREATE INDEX "idx_tenants_status" ON "tenants" ("status");

-- ============================================================================
-- Tenant Secrets
-- ============================================================================

CREATE TABLE "tenant_secrets" (
  "id" uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "purpose" text NOT NULL,
  "ciphertext" bytea NOT NULL,
  "iv" bytea NOT NULL,
  "key_version" smallint NOT NULL DEFAULT 1,
  "metadata" jsonb DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  CONSTRAINT "unique_tenant_secret_purpose" UNIQUE ("tenant_id", "purpose")
);

CREATE INDEX "idx_tenant_secrets_tenant_id" ON "tenant_secrets" ("tenant_id");

-- ============================================================================
-- Clusters and Groups
-- ============================================================================

CREATE TABLE "clusters" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "last_check_in_at" timestamptz NOT NULL DEFAULT NOW(),
  "name" text NOT NULL CHECK (name <> ''),
  "metadata" text,
  "version" text,
  "kubernetes_version" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_cluster_name_per_tenant" UNIQUE ("tenant_id", "name")
);

CREATE INDEX "idx_clusters_tenant_id" ON "clusters" ("tenant_id");
CREATE INDEX "idx_clusters_deleted_at" ON "clusters" ("deleted_at");

CREATE TABLE "cluster_groups" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text NOT NULL CHECK (name <> ''),
  "priority" integer NOT NULL DEFAULT 0,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_cluster_group_name_per_tenant" UNIQUE ("tenant_id", "name")
);

CREATE INDEX "idx_cluster_groups_tenant_id" ON "cluster_groups" ("tenant_id");
CREATE INDEX "idx_cluster_groups_deleted_at" ON "cluster_groups" ("deleted_at");

CREATE TABLE "namespaces" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text NOT NULL,
  "cluster_id" uuid NOT NULL REFERENCES "clusters"("id") ON DELETE CASCADE,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_namespace_per_cluster_per_tenant" UNIQUE ("tenant_id", "cluster_id", "name")
);

CREATE INDEX "idx_namespaces_tenant_id" ON "namespaces" ("tenant_id");
CREATE INDEX "idx_namespaces_deleted_at" ON "namespaces" ("deleted_at");

CREATE TABLE "group_relationships" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "cluster_id" uuid NOT NULL REFERENCES "clusters"("id") ON DELETE CASCADE,
  "cluster_group_id" uuid NOT NULL REFERENCES "cluster_groups"("id") ON DELETE CASCADE,
  PRIMARY KEY ("cluster_id", "cluster_group_id")
);

-- ============================================================================
-- Repos and Branches
-- ============================================================================

CREATE TABLE "repos" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "org" text NOT NULL,
  "repo" text NOT NULL,
  "provider" text NOT NULL DEFAULT 'github',
  "host" text NOT NULL DEFAULT 'github.com',
  "web_base_url" text NOT NULL DEFAULT 'https://github.com',
  "api_base_url" text NOT NULL DEFAULT 'https://api.github.com',
  "host_ci" text GENERATED ALWAYS AS (LOWER(host)) STORED,
  "org_ci" text GENERATED ALWAYS AS (LOWER(org)) STORED,
  "repo_ci" text GENERATED ALWAYS AS (LOWER(repo)) STORED,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_repo_identity_per_tenant" UNIQUE ("tenant_id", "host_ci", "org_ci", "repo_ci")
);

CREATE INDEX "idx_repos_tenant_id" ON "repos" ("tenant_id");

CREATE TABLE "repo_branches" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "branch" text NOT NULL,
  "repo_id" uuid NOT NULL REFERENCES "repos"("id") ON DELETE CASCADE,
  "service_autosync" uuid[],
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_repo_branch_per_tenant" UNIQUE ("tenant_id", "repo_id", "branch")
);

CREATE INDEX "idx_repo_branches_tenant_id" ON "repo_branches" ("tenant_id");

-- ============================================================================
-- Webhooks
-- ============================================================================

CREATE TABLE "repo_webhooks" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "repo_id" uuid NOT NULL REFERENCES "repos"("id") ON DELETE CASCADE,
  "provider_webhook_id" bigint,
  "secret_hash" text NOT NULL,
  "secret" text,
  "active" boolean NOT NULL DEFAULT true,
  "last_delivery_at" timestamptz,
  "last_error" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_repo_webhook_per_tenant" UNIQUE ("tenant_id", "repo_id")
);

CREATE INDEX "idx_repo_webhooks_tenant_id" ON "repo_webhooks" ("tenant_id");
CREATE INDEX "idx_repo_webhooks_repo_id" ON "repo_webhooks" ("repo_id") WHERE "deleted_at" IS NULL;

CREATE TABLE "repo_webhook_events" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "webhook_id" uuid NOT NULL REFERENCES "repo_webhooks"("id") ON DELETE CASCADE,
  "delivery_id" text NOT NULL,
  "event_type" text NOT NULL,
  "ref" text,
  "before_sha" text,
  "after_sha" text,
  "pusher" text,
  "processed_at" timestamptz,
  "processing_error" text,
  "matched_paths" text[],
  "updated_service_versions" uuid[],
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_delivery_per_tenant" UNIQUE ("tenant_id", "delivery_id")
);

CREATE INDEX "idx_repo_webhook_events_webhook_id" ON "repo_webhook_events" ("webhook_id");
CREATE INDEX "idx_repo_webhook_events_created_at" ON "repo_webhook_events" ("created_at");

-- ============================================================================
-- Service Definitions
-- ============================================================================

CREATE TABLE "service_definitions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "repo_branch_id" uuid REFERENCES "repo_branches"("id") ON DELETE SET NULL,
  "name" text CHECK (name IS NULL OR name = LOWER(name)),
  "source_branch_requirements" text,
  "manifest_path_template" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_service_definition_per_branch_per_tenant" UNIQUE ("tenant_id", "repo_branch_id", "name")
);

CREATE INDEX "idx_service_definitions_tenant_id" ON "service_definitions" ("tenant_id");

COMMENT ON COLUMN service_definitions.manifest_path_template IS
  'Path template for manifests. MUST contain {service}, {cluster}, and {namespace} placeholders.';

CREATE TABLE "service_definition_cluster_group_relationships" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "service_definition_id" uuid NOT NULL REFERENCES "service_definitions"("id") ON DELETE CASCADE,
  "cluster_group_id" uuid NOT NULL REFERENCES "cluster_groups"("id") ON DELETE CASCADE,
  PRIMARY KEY ("service_definition_id", "cluster_group_id")
);

-- ============================================================================
-- Service Versions
-- ============================================================================

CREATE TABLE "service_versions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "service_definition_id" uuid NOT NULL REFERENCES "service_definitions"("id") ON DELETE CASCADE,
  "namespace_id" uuid NOT NULL REFERENCES "namespaces"("id") ON DELETE CASCADE,
  "version" text NOT NULL,
  "git_sha" text NOT NULL,
  "git_sha_short" text,
  "path" text NOT NULL,
  "hash" text NOT NULL,
  "source" text NOT NULL DEFAULT 'api',
  "source_metadata" jsonb,
  "deprecated_at" timestamptz,
  "deprecated_by" text,
  "deprecated_reason" text,
  "pinned_at" timestamptz,
  "pinned_by" text,
  "webhook_event_id" uuid REFERENCES "repo_webhook_events"("id") ON DELETE SET NULL,
  "is_directory_pattern" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "idx_service_versions_active_unique"
  ON "service_versions" ("service_definition_id", "namespace_id")
  WHERE "deprecated_at" IS NULL;

CREATE INDEX "idx_service_versions_tenant_id" ON "service_versions" ("tenant_id");
CREATE INDEX "idx_service_versions_service_definition" ON "service_versions" ("service_definition_id");
CREATE INDEX "idx_service_versions_namespace" ON "service_versions" ("namespace_id");
CREATE INDEX "idx_service_versions_git_sha" ON "service_versions" ("git_sha");
CREATE INDEX "idx_service_versions_hash" ON "service_versions" ("hash");
CREATE INDEX "idx_service_versions_active" ON "service_versions" ("deprecated_at") WHERE "deprecated_at" IS NULL;

-- ============================================================================
-- Releases and Diffs
-- ============================================================================

CREATE TABLE "releases" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "service_id" uuid,
  "namespace_id" uuid REFERENCES "namespaces"("id") ON DELETE CASCADE,
  "hash" text,
  "path" text,
  "name" text,
  "version" text,
  "repo_branch_id" uuid REFERENCES "repo_branches"("id") ON DELETE SET NULL,
  "git_sha" text,
  "approved_by" text,
  "approved_at" timestamptz,
  "unapproved_by" text,
  "unapproved_at" timestamptz,
  "unapproved_reason" text,
  "started_first_install_at" timestamptz,
  "failed_first_install_at" timestamptz,
  "completed_first_install_at" timestamptz,
  "started_update_install_at" timestamptz,
  "failed_update_install_at" timestamptz,
  "completed_update_install_at" timestamptz,
  "marked_for_deletion_at" timestamptz,
  "started_delete_at" timestamptz,
  "failed_delete_at" timestamptz,
  "completed_delete_at" timestamptz,
  "deprecated_at" timestamptz,
  "diff_generation" integer NOT NULL DEFAULT 0,
  "diff_service_id" uuid,
  "diff_namespace_id" uuid,
  "last_diff_at" timestamptz,
  "is_diff" boolean,
  "previous_installed_hash" text,
  "manually_selected_at" timestamptz,
  "last_sync_at" timestamptz,
  "in_cluster_manifest_storage_url" text,
  "is_directory_pattern" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_release_per_namespace_per_tenant" UNIQUE ("tenant_id", "namespace_id", "service_id")
);

CREATE INDEX "idx_releases_tenant_id" ON "releases" ("tenant_id");

CREATE TABLE "resource_diffs" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "release_id" uuid NOT NULL REFERENCES "releases"("id") ON DELETE CASCADE,
  "diff_generation" integer NOT NULL,
  "key" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "body" text,
  "change_order" text[],
  "storage_url" text,
  PRIMARY KEY ("key", "release_id", "diff_generation")
);

-- ============================================================================
-- Agent Users and Auth
-- ============================================================================

CREATE TABLE "users" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text NOT NULL,
  "hash" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_agent_user_per_tenant" UNIQUE ("tenant_id", "name")
);

CREATE INDEX "idx_users_tenant_id" ON "users" ("tenant_id");
CREATE INDEX "idx_users_deleted_at" ON "users" ("deleted_at");

CREATE TABLE "refresh_tokens" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "token_hash" text NOT NULL UNIQUE,
  "user_id" uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "cluster_id" uuid REFERENCES "clusters"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "expires_at" timestamptz NOT NULL,
  "revoked_at" timestamptz,
  "parent_token_id" uuid REFERENCES "refresh_tokens"("id") ON DELETE SET NULL,
  "replaced_by_token_id" uuid,
  "user_agent" text,
  "ip_address" text
);

CREATE INDEX "idx_refresh_tokens_hash" ON "refresh_tokens"("token_hash");
CREATE INDEX "idx_refresh_tokens_user_active" ON "refresh_tokens"("user_id", "expires_at") WHERE "revoked_at" IS NULL;
CREATE INDEX "idx_refresh_tokens_expires" ON "refresh_tokens"("expires_at") WHERE "revoked_at" IS NULL;

-- ============================================================================
-- UI Users and Sessions
-- ============================================================================

CREATE TABLE "ui_users" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "username" text NOT NULL,
  "password_hash" text NOT NULL,
  "roles" text[] NOT NULL DEFAULT '{}'::text[],
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_ui_user_per_tenant" UNIQUE ("tenant_id", "username")
);

CREATE INDEX "idx_ui_users_tenant_id" ON "ui_users" ("tenant_id");
CREATE INDEX "idx_ui_users_deleted_at" ON "ui_users" ("deleted_at");

CREATE TABLE "ui_sessions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "user_id" uuid NOT NULL REFERENCES "ui_users"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "expires_at" timestamptz NOT NULL,
  "revoked_at" timestamptz,
  "last_seen_at" timestamptz,
  "token_hash" text NOT NULL UNIQUE,
  PRIMARY KEY ("id")
);

CREATE INDEX "idx_ui_sessions_tenant_id" ON "ui_sessions" ("tenant_id");
CREATE INDEX "idx_ui_sessions_user_active" ON "ui_sessions" ("user_id", "expires_at") WHERE "revoked_at" IS NULL;
CREATE INDEX "idx_ui_sessions_expires" ON "ui_sessions" ("expires_at") WHERE "revoked_at" IS NULL;

-- ============================================================================
-- Errors
-- ============================================================================

CREATE TABLE "hive_errors" (
  "id" uuid DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deprecated_at" timestamptz,
  "cluster_id" uuid REFERENCES "clusters"("id") ON DELETE CASCADE,
  "message" text,
  "is_deprecated" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_cluster_message_per_tenant" UNIQUE ("tenant_id", "cluster_id", "message")
);

CREATE TABLE "release_errors" (
  "id" uuid DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "release_id" uuid REFERENCES "releases"("id") ON DELETE CASCADE,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deprecated_at" timestamptz,
  "message" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_release_message_per_tenant" UNIQUE ("tenant_id", "release_id", "message")
);

-- ============================================================================
-- Helper Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION match_path_template(
  template text,
  file_path text
) RETURNS jsonb AS $$
DECLARE
  template_parts text[];
  file_parts text[];
  result jsonb := '{}';
  i integer;
  part text;
  file_part text;
BEGIN
  template_parts := string_to_array(template, '/');
  file_parts := string_to_array(file_path, '/');

  IF array_length(file_parts, 1) < array_length(template_parts, 1) THEN
    RETURN NULL;
  END IF;

  FOR i IN 1..array_length(template_parts, 1) LOOP
    part := template_parts[i];
    file_part := file_parts[i];

    IF part LIKE '{%}' THEN
      result := result || jsonb_build_object(
        trim(both '{}' from part),
        file_part
      );
    ELSIF part != file_part THEN
      RETURN NULL;
    END IF;
  END LOOP;

  IF result ? 'service' AND result ? 'cluster' AND result ? 'namespace' THEN
    RETURN result;
  ELSE
    RETURN NULL;
  END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- RLS helper: Get current tenant from session variable
-- MUST be STABLE (not IMMUTABLE) because it reads session state that can change
-- Handles empty string case (current_setting returns '' not NULL when unset)
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid AS $$
  SELECT CASE 
    WHEN current_setting('app.tenant_id', true) = '' THEN NULL
    WHEN current_setting('app.tenant_id', true) IS NULL THEN NULL
    ELSE current_setting('app.tenant_id', true)::uuid
  END;
$$ LANGUAGE SQL STABLE;

-- ============================================================================
-- SECURITY DEFINER Auth Functions (bypass RLS for authentication)
-- ============================================================================
-- These functions run with owner privileges, bypassing RLS.
-- Used for authentication lookups where tenant context isn't known yet.

-- Lookup UI session by token hash (for hive-hq)
-- Returns user info + tenant_id to establish context
CREATE OR REPLACE FUNCTION auth_lookup_ui_session(p_token_hash text)
RETURNS TABLE (
  user_id uuid,
  tenant_id uuid,
  username text,
  roles text[],
  tenant_name text,
  session_expires_at timestamptz
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id as user_id,
    u.tenant_id,
    u.username,
    u.roles,
    t.name as tenant_name,
    s.expires_at as session_expires_at
  FROM ui_sessions s
  JOIN ui_users u ON s.user_id = u.id
  LEFT JOIN tenants t ON t.id = u.tenant_id
  WHERE s.token_hash = p_token_hash
    AND s.expires_at > NOW()
    AND s.revoked_at IS NULL
    AND u.deleted_at IS NULL;
  
  -- Touch the session (best effort)
  UPDATE ui_sessions SET last_seen_at = NOW() WHERE token_hash = p_token_hash;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Lookup agent user by username (for hive-server)
-- Returns user credentials + tenant_id to establish context
CREATE OR REPLACE FUNCTION auth_lookup_agent_user(p_username text)
RETURNS TABLE (
  user_id uuid,
  tenant_id uuid,
  password_hash text
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id as user_id,
    u.tenant_id,
    u.hash as password_hash
  FROM users u
  WHERE u.name = p_username
    AND u.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Lookup cluster by name (for hive-server JWT claims)
CREATE OR REPLACE FUNCTION auth_lookup_cluster_by_name(p_cluster_name text, p_tenant_id uuid)
RETURNS uuid AS $$
  SELECT id FROM clusters 
  WHERE name = p_cluster_name 
    AND tenant_id = p_tenant_id
    AND deleted_at IS NULL;
$$ LANGUAGE SQL STABLE SECURITY DEFINER;

-- Insert refresh token (for hive-server login)
CREATE OR REPLACE FUNCTION auth_insert_refresh_token(
  p_token_hash text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_cluster_id uuid,
  p_expires_at timestamptz,
  p_user_agent text,
  p_ip_address text
) RETURNS void AS $$
BEGIN
  INSERT INTO refresh_tokens (token_hash, user_id, tenant_id, cluster_id, expires_at, user_agent, ip_address)
  VALUES (p_token_hash, p_user_id, p_tenant_id, p_cluster_id, p_expires_at, p_user_agent, p_ip_address);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Lookup refresh token for token refresh (for hive-server)
-- Joins with users table to get username for JWT generation
CREATE OR REPLACE FUNCTION auth_lookup_refresh_token(p_token_hash text)
RETURNS TABLE (
  token_id uuid,
  user_id uuid,
  tenant_id uuid,
  cluster_id uuid,
  expires_at timestamptz,
  revoked_at timestamptz,
  replaced_by_token_id uuid,
  username text
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    rt.id as token_id,
    rt.user_id,
    rt.tenant_id,
    rt.cluster_id,
    rt.expires_at,
    rt.revoked_at,
    rt.replaced_by_token_id,
    u.name as username
  FROM refresh_tokens rt
  JOIN users u ON rt.user_id = u.id
  WHERE rt.token_hash = p_token_hash
    AND u.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Insert new refresh token during rotation (for hive-server)
CREATE OR REPLACE FUNCTION auth_rotate_refresh_token(
  p_old_token_id uuid,
  p_new_token_hash text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_cluster_id uuid,
  p_expires_at timestamptz
) RETURNS uuid AS $$
DECLARE
  v_new_token_id uuid;
BEGIN
  -- Insert new token linked to parent
  INSERT INTO refresh_tokens (token_hash, user_id, tenant_id, cluster_id, expires_at, parent_token_id)
  VALUES (p_new_token_hash, p_user_id, p_tenant_id, p_cluster_id, p_expires_at, p_old_token_id)
  RETURNING id INTO v_new_token_id;
  
  -- Revoke old token and link to new one
  UPDATE refresh_tokens 
  SET revoked_at = NOW(), replaced_by_token_id = v_new_token_id
  WHERE id = p_old_token_id;
  
  RETURN v_new_token_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Revoke token family (for replay attack detection)
CREATE OR REPLACE FUNCTION auth_revoke_token_family(p_root_token_id uuid) RETURNS void AS $$
BEGIN
  -- Revoke all tokens in the family tree
  WITH RECURSIVE token_tree AS (
    SELECT id FROM refresh_tokens WHERE id = p_root_token_id
    UNION ALL
    SELECT rt.id FROM refresh_tokens rt
    JOIN token_tree tt ON rt.parent_token_id = tt.id
  )
  UPDATE refresh_tokens SET revoked_at = NOW()
  WHERE id IN (SELECT id FROM token_tree) AND revoked_at IS NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Revoke refresh token
CREATE OR REPLACE FUNCTION auth_revoke_refresh_token(p_token_hash text) RETURNS void AS $$
BEGIN
  UPDATE refresh_tokens SET revoked = true WHERE token_hash = p_token_hash;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Delete expired refresh tokens (cleanup job)
CREATE OR REPLACE FUNCTION auth_cleanup_expired_tokens() RETURNS void AS $$
BEGIN
  DELETE FROM refresh_tokens WHERE expires_at < NOW();
  DELETE FROM ui_sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Register tenant + first user (for hive-hq registration)
-- Returns tenant_id for subsequent operations
CREATE OR REPLACE FUNCTION auth_register_tenant(
  p_domain text,
  p_tenant_name text,
  p_username text,
  p_password_hash text
) RETURNS TABLE (
  tenant_id uuid,
  user_id uuid
) AS $$
DECLARE
  v_tenant_id uuid;
  v_user_id uuid;
BEGIN
  -- Create tenant
  INSERT INTO tenants (domain, name, status)
  VALUES (p_domain, p_tenant_name, 'active')
  RETURNING id INTO v_tenant_id;
  
  -- Create first user (admin)
  INSERT INTO ui_users (tenant_id, username, password_hash, roles)
  VALUES (v_tenant_id, p_username, p_password_hash, ARRAY['admin'])
  RETURNING id INTO v_user_id;
  
  tenant_id := v_tenant_id;
  user_id := v_user_id;
  RETURN NEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create UI session (for hive-hq login)
CREATE OR REPLACE FUNCTION auth_create_ui_session(
  p_token_hash text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_expires_at timestamptz
) RETURNS void AS $$
BEGIN
  INSERT INTO ui_sessions (token_hash, user_id, tenant_id, expires_at)
  VALUES (p_token_hash, p_user_id, p_tenant_id, p_expires_at);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Revoke UI session by token hash (for hive-hq logout)
CREATE OR REPLACE FUNCTION auth_revoke_ui_session(p_token_hash text) RETURNS void AS $$
BEGIN
  UPDATE ui_sessions SET revoked_at = NOW()
  WHERE token_hash = p_token_hash AND revoked_at IS NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Log hive error (for hive-server error reporting, bypasses RLS)
CREATE OR REPLACE FUNCTION log_hive_error(
  p_tenant_id uuid,
  p_cluster_id uuid,
  p_message text
) RETURNS void AS $$
BEGIN
  INSERT INTO hive_errors (tenant_id, cluster_id, message)
  VALUES (p_tenant_id, p_cluster_id, p_message)
  ON CONFLICT (cluster_id, message)
  DO UPDATE SET deprecated_at = NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Log release error (for hive-server error reporting, bypasses RLS)
CREATE OR REPLACE FUNCTION log_release_error(
  p_tenant_id uuid,
  p_release_id uuid,
  p_message text,
  p_severity text DEFAULT 'error'
) RETURNS void AS $$
BEGIN
  INSERT INTO release_errors (tenant_id, release_id, message, severity)
  VALUES (p_tenant_id, p_release_id, p_message, p_severity)
  ON CONFLICT (release_id, message) DO NOTHING;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Lookup UI user for login (by username and tenant domain)
CREATE OR REPLACE FUNCTION auth_lookup_ui_user_for_login(p_username text, p_domain text)
RETURNS TABLE (
  user_id uuid,
  tenant_id uuid,
  password_hash text,
  username text,
  roles text[],
  tenant_name text
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id as user_id,
    u.tenant_id,
    u.password_hash,
    u.username,
    u.roles,
    t.name as tenant_name
  FROM ui_users u
  JOIN tenants t ON u.tenant_id = t.id
  WHERE u.username = p_username
    AND t.domain = p_domain
    AND u.deleted_at IS NULL
    AND t.status = 'active';
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- Row-Level Security (RLS)
-- ============================================================================

-- Enable RLS on all tenant-bound tables
ALTER TABLE "tenants" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tenant_secrets" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "clusters" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "cluster_groups" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "namespaces" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "group_relationships" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "repos" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "repo_branches" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "repo_webhooks" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "repo_webhook_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "service_definitions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "service_definition_cluster_group_relationships" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "service_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "releases" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "resource_diffs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "refresh_tokens" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ui_users" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ui_sessions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "hive_errors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "release_errors" ENABLE ROW LEVEL SECURITY;

-- FORCE RLS applies policies even to table owner (hive_user)
-- All tenant-scoped tables now enforce RLS:
-- - hive-hq uses SECURITY DEFINER functions for auth lookups
-- - hive-server extracts tenant_id from JWT and sets context in transactions
ALTER TABLE "tenant_secrets" FORCE ROW LEVEL SECURITY;
ALTER TABLE "clusters" FORCE ROW LEVEL SECURITY;
ALTER TABLE "cluster_groups" FORCE ROW LEVEL SECURITY;
ALTER TABLE "namespaces" FORCE ROW LEVEL SECURITY;
ALTER TABLE "group_relationships" FORCE ROW LEVEL SECURITY;
ALTER TABLE "repos" FORCE ROW LEVEL SECURITY;
ALTER TABLE "repo_branches" FORCE ROW LEVEL SECURITY;
ALTER TABLE "repo_webhooks" FORCE ROW LEVEL SECURITY;
ALTER TABLE "repo_webhook_events" FORCE ROW LEVEL SECURITY;
ALTER TABLE "service_definitions" FORCE ROW LEVEL SECURITY;
ALTER TABLE "service_definition_cluster_group_relationships" FORCE ROW LEVEL SECURITY;
ALTER TABLE "service_versions" FORCE ROW LEVEL SECURITY;
ALTER TABLE "releases" FORCE ROW LEVEL SECURITY;
ALTER TABLE "resource_diffs" FORCE ROW LEVEL SECURITY;
ALTER TABLE "users" FORCE ROW LEVEL SECURITY;
ALTER TABLE "refresh_tokens" FORCE ROW LEVEL SECURITY;
ALTER TABLE "ui_users" FORCE ROW LEVEL SECURITY;
ALTER TABLE "ui_sessions" FORCE ROW LEVEL SECURITY;
ALTER TABLE "hive_errors" FORCE ROW LEVEL SECURITY;
ALTER TABLE "release_errors" FORCE ROW LEVEL SECURITY;

-- RLS Policies

-- Tenants: allow all (tenant selection handled at application layer)
CREATE POLICY "tenants_isolation" ON tenants
  USING (true) WITH CHECK (true);

-- All other tables: enforce tenant_id = current_tenant_id()
CREATE POLICY "tenant_secrets_isolation" ON tenant_secrets
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "clusters_isolation" ON clusters
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "cluster_groups_isolation" ON cluster_groups
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "namespaces_isolation" ON namespaces
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "group_relationships_isolation" ON group_relationships
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "repos_isolation" ON repos
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "repo_branches_isolation" ON repo_branches
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "repo_webhooks_isolation" ON repo_webhooks
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "repo_webhook_events_isolation" ON repo_webhook_events
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "service_definitions_isolation" ON service_definitions
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "service_definition_cluster_group_relationships_isolation" ON service_definition_cluster_group_relationships
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "service_versions_isolation" ON service_versions
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "releases_isolation" ON releases
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "resource_diffs_isolation" ON resource_diffs
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "users_isolation" ON users
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "refresh_tokens_isolation" ON refresh_tokens
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "ui_users_isolation" ON ui_users
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "ui_sessions_isolation" ON ui_sessions
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "hive_errors_isolation" ON hive_errors
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY "release_errors_isolation" ON release_errors
  USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- Role Setup (Two-Role Pattern for RLS)
-- ============================================================================
-- 
-- This schema uses a two-role pattern for proper RLS enforcement:
--
--   hive_admin (superuser/owner):
--     - Owns all tables and SECURITY DEFINER functions
--     - Bypasses RLS (table owner privilege)
--     - Used for migrations, admin tasks, backup/restore
--     - SECURITY DEFINER functions execute with this role's privileges
--
--   hive_user (application role):
--     - Used by hive-server and hive-hq application connections
--     - Has DML privileges (SELECT, INSERT, UPDATE, DELETE) but does NOT own tables
--     - Subject to RLS automatically (non-owner)
--     - No need for FORCE RLS since non-owners are always subject to RLS
--
-- With this pattern, FORCE ROW LEVEL SECURITY is technically not needed for
-- hive_user since non-owners are always subject to RLS. We keep FORCE RLS
-- as defense-in-depth in case applications accidentally connect as owner.
--
-- Role creation (run as superuser before migration):
--   CREATE ROLE hive_admin WITH LOGIN PASSWORD 'admin_password';
--   CREATE ROLE hive_user WITH LOGIN PASSWORD 'app_password';
--   GRANT hive_user TO hive_admin;  -- admin can act as app user for testing
--
-- ============================================================================

-- Grant app-level privileges to hive_user (if exists)
-- hive_user does NOT own tables - this is intentional for RLS
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hive_user') THEN
        -- Grant DML on all tables (no ownership transfer)
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hive_user;
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO hive_user;
        GRANT USAGE ON SCHEMA public TO hive_user;

        -- Future tables also get these grants
        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
          GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hive_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
          GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO hive_user;
          
        -- Grant EXECUTE on SECURITY DEFINER functions (owned by admin/postgres)
        -- These functions bypass RLS and are needed for auth operations
        GRANT EXECUTE ON FUNCTION auth_lookup_ui_session(text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_agent_user(text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_cluster_by_name(text, uuid) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_insert_refresh_token(text, uuid, uuid, uuid, timestamptz, text, text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_refresh_token(text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_rotate_refresh_token(uuid, text, uuid, uuid, uuid, timestamptz) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_token_family(uuid) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_refresh_token(text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_cleanup_expired_tokens() TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_register_tenant(text, text, text, text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_create_ui_session(text, uuid, uuid, timestamptz) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_ui_session(text) TO hive_user;
        GRANT EXECUTE ON FUNCTION log_hive_error(uuid, uuid, text) TO hive_user;
        GRANT EXECUTE ON FUNCTION log_release_error(uuid, uuid, text, text) TO hive_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_ui_user_for_login(text, text) TO hive_user;
        GRANT EXECUTE ON FUNCTION current_tenant_id() TO hive_user;
        GRANT EXECUTE ON FUNCTION match_path_template(text, text) TO hive_user;
    END IF;
    
    -- hq_user is the same as hive_user (used by hive-hq API)
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hq_user') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hq_user;
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO hq_user;
        GRANT USAGE ON SCHEMA public TO hq_user;

        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
          GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hq_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
          GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO hq_user;
          
        GRANT EXECUTE ON FUNCTION auth_lookup_ui_session(text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_agent_user(text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_cluster_by_name(text, uuid) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_insert_refresh_token(text, uuid, uuid, uuid, timestamptz, text, text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_refresh_token(text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_rotate_refresh_token(uuid, text, uuid, uuid, uuid, timestamptz) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_token_family(uuid) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_refresh_token(text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_cleanup_expired_tokens() TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_register_tenant(text, text, text, text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_create_ui_session(text, uuid, uuid, timestamptz) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_revoke_ui_session(text) TO hq_user;
        GRANT EXECUTE ON FUNCTION log_hive_error(uuid, uuid, text) TO hq_user;
        GRANT EXECUTE ON FUNCTION log_release_error(uuid, uuid, text, text) TO hq_user;
        GRANT EXECUTE ON FUNCTION auth_lookup_ui_user_for_login(text, text) TO hq_user;
        GRANT EXECUTE ON FUNCTION current_tenant_id() TO hq_user;
        GRANT EXECUTE ON FUNCTION match_path_template(text, text) TO hq_user;
    END IF;
END $$;
