-- BeeCD initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- Clusters and Groups
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "clusters" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "last_check_in_at" timestamptz NOT NULL DEFAULT NOW(),
  "name" text NOT NULL CHECK (name <> ''),
  "metadata" text,
  "version" text,
  "kubernetes_version" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_cluster_name" UNIQUE ("name")
);

CREATE INDEX IF NOT EXISTS "idx_clusters_deleted_at" ON "clusters" ("deleted_at");

CREATE TABLE IF NOT EXISTS "cluster_groups" (
  "id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text NOT NULL CHECK (name <> ''),
  "priority" integer NOT NULL DEFAULT 0,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_name" UNIQUE ("name")
);

CREATE INDEX IF NOT EXISTS "idx_cluster_groups_deleted_at" ON "cluster_groups" ("deleted_at");

CREATE TABLE IF NOT EXISTS "namespaces" (
  "id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text,
  "cluster_id" uuid,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_namespaces_cluster" FOREIGN KEY ("cluster_id") REFERENCES "clusters"("id"),
  CONSTRAINT "unique_cluster_id_namespace" UNIQUE ("cluster_id", "name")
);

CREATE INDEX IF NOT EXISTS "idx_namespaces_deleted_at" ON "namespaces" ("deleted_at");

CREATE TABLE IF NOT EXISTS "group_relationships" (
  "cluster_id" uuid,
  "cluster_group_id" uuid,
  PRIMARY KEY ("cluster_id", "cluster_group_id"),
  CONSTRAINT "fk_group_relationships_cluster" FOREIGN KEY ("cluster_id") REFERENCES "clusters"("id"),
  CONSTRAINT "fk_group_relationships_cluster_group" FOREIGN KEY ("cluster_group_id") REFERENCES "cluster_groups"("id") ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- Repos and Branches
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "repos" (
  "id" uuid,
  "org" text NOT NULL,
  "repo" text NOT NULL,
  "provider" text NOT NULL DEFAULT 'github',
  "host" text NOT NULL DEFAULT 'github.com',
  "web_base_url" text NOT NULL DEFAULT 'https://github.com',
  "api_base_url" text NOT NULL DEFAULT 'https://api.github.com',
  -- Generated lowercase columns for case-insensitive uniqueness
  "host_ci" text GENERATED ALWAYS AS (LOWER(host)) STORED,
  "org_ci" text GENERATED ALWAYS AS (LOWER(org)) STORED,
  "repo_ci" text GENERATED ALWAYS AS (LOWER(repo)) STORED,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_repo_identity_ci" UNIQUE ("host_ci", "org_ci", "repo_ci")
);

CREATE TABLE IF NOT EXISTS "repo_branches" (
  "id" uuid,
  "branch" text,
  "repo_id" uuid,
  "service_autosync" uuid[],
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_repo_branches_repo" FOREIGN KEY ("repo_id") REFERENCES "repos"("id"),
  CONSTRAINT "unique_repo_id_branch" UNIQUE ("repo_id", "branch")
);

-- -----------------------------------------------------------------------------
-- Webhooks (provider-agnostic)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "repo_webhooks" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "repo_id" uuid NOT NULL,
  "provider_webhook_id" bigint,
  "secret_hash" text NOT NULL,
  "secret" text,
  "active" boolean NOT NULL DEFAULT true,
  "last_delivery_at" timestamptz,
  "last_error" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_repo_webhooks_repo" FOREIGN KEY ("repo_id") REFERENCES "repos"("id") ON DELETE CASCADE,
  CONSTRAINT "unique_repo_webhook" UNIQUE ("repo_id")
);

CREATE INDEX IF NOT EXISTS "idx_repo_webhooks_repo_id" ON "repo_webhooks" ("repo_id") WHERE "deleted_at" IS NULL;

CREATE TABLE IF NOT EXISTS "repo_webhook_events" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "webhook_id" uuid NOT NULL,
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
  CONSTRAINT "fk_repo_webhook_events_webhook" FOREIGN KEY ("webhook_id") REFERENCES "repo_webhooks"("id") ON DELETE CASCADE,
  CONSTRAINT "unique_delivery" UNIQUE ("delivery_id")
);

CREATE INDEX IF NOT EXISTS "idx_repo_webhook_events_webhook_id" ON "repo_webhook_events" ("webhook_id");
CREATE INDEX IF NOT EXISTS "idx_repo_webhook_events_created_at" ON "repo_webhook_events" ("created_at");

-- -----------------------------------------------------------------------------
-- Service Definitions
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "service_definitions" (
  "id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "repo_branch_id" uuid,
  "name" text CHECK (name IS NULL OR name = LOWER(name)),
  "source_branch_requirements" text,
  "manifest_path_template" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_repo_branch" UNIQUE ("repo_branch_id", "name"),
  CONSTRAINT "fk_service_definitions_repo_branch" FOREIGN KEY ("repo_branch_id") REFERENCES "repo_branches"("id")
);

COMMENT ON COLUMN service_definitions.manifest_path_template IS
  'Path template for manifests in the repo. MUST contain {service}, {cluster}, and {namespace} placeholders. Example: manifests/{cluster}/{namespace}/{service}';

CREATE TABLE IF NOT EXISTS "service_definition_cluster_group_relationships" (
  "service_definition_id" uuid,
  "cluster_group_id" uuid,
  PRIMARY KEY ("service_definition_id", "cluster_group_id"),
  CONSTRAINT "fk_group_relationships_service_definition" FOREIGN KEY ("service_definition_id") REFERENCES "service_definitions"("id"),
  CONSTRAINT "fk_group_relationships_cluster_group" FOREIGN KEY ("cluster_group_id") REFERENCES "cluster_groups"("id") ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- Service Versions
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "service_versions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "service_definition_id" uuid NOT NULL,
  "namespace_id" uuid NOT NULL,
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
  "webhook_event_id" uuid,
  "is_directory_pattern" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_service_versions_service_definition" FOREIGN KEY ("service_definition_id") REFERENCES "service_definitions"("id") ON DELETE CASCADE,
  CONSTRAINT "fk_service_versions_namespace" FOREIGN KEY ("namespace_id") REFERENCES "namespaces"("id") ON DELETE CASCADE,
  CONSTRAINT "service_versions_webhook_event_id_fkey" FOREIGN KEY ("webhook_event_id") REFERENCES "repo_webhook_events"("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_service_versions_active_unique"
  ON "service_versions" ("service_definition_id", "namespace_id")
  WHERE "deprecated_at" IS NULL;

CREATE INDEX IF NOT EXISTS "idx_service_versions_service_definition" ON "service_versions" ("service_definition_id");
CREATE INDEX IF NOT EXISTS "idx_service_versions_namespace" ON "service_versions" ("namespace_id");
CREATE INDEX IF NOT EXISTS "idx_service_versions_git_sha" ON "service_versions" ("git_sha");
CREATE INDEX IF NOT EXISTS "idx_service_versions_hash" ON "service_versions" ("hash");
CREATE INDEX IF NOT EXISTS "idx_service_versions_active" ON "service_versions" ("deprecated_at") WHERE "deprecated_at" IS NULL;

COMMENT ON TABLE service_versions IS
  'Stores version information for service definitions. Each row represents a specific version of a service that can be deployed to a namespace.';

COMMENT ON COLUMN service_versions.source IS
  'How this version was registered: webhook (from push), api (legacy/manual)';

COMMENT ON COLUMN service_versions.hash IS
  'Content hash of the rendered Kubernetes manifest. Used to detect changes and for content-addressable storage.';

COMMENT ON COLUMN service_versions.pinned_at IS
  'When set, this version will not be automatically deprecated by incoming webhooks. User must explicitly unpin or deprecate.';

COMMENT ON COLUMN service_versions.pinned_by IS
  'User or system that pinned this version.';

COMMENT ON COLUMN service_versions.webhook_event_id IS
  'Reference to the repo_webhook_events row that created this version (if source is webhook).';

COMMENT ON COLUMN service_versions.is_directory_pattern IS
  'When true, path contains a glob pattern (e.g., "prod/default/nginx/*.yaml") and hive server should fetch all matching files. When false, path is a single file.';

COMMENT ON COLUMN service_versions.path IS
  'Path to manifest in repo. Either a single file path (e.g., "deploy/prod/app.yaml") or a glob pattern for directories (e.g., "deploy/prod/app/*.yaml"). See is_directory_pattern.';

-- -----------------------------------------------------------------------------
-- Releases and Diffs
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "releases" (
  "id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "service_id" uuid,
  "namespace_id" uuid,
  "hash" text,
  "path" text,
  "name" text,
  "version" text,
  "repo_branch_id" uuid,
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
  CONSTRAINT "unique_service_id_namespace_id" UNIQUE ("namespace_id", "service_id"),
  CONSTRAINT "fk_repo_branch" FOREIGN KEY ("repo_branch_id") REFERENCES "repo_branches"("id"),
  CONSTRAINT "fk_filedata_namespace" FOREIGN KEY ("namespace_id") REFERENCES "namespaces"("id")
);

COMMENT ON COLUMN releases.is_directory_pattern IS
  'When true, path contains a glob pattern and hive server should fetch all matching files from directory. When false, path is a single file.';

CREATE TABLE IF NOT EXISTS "resource_diffs" (
  "release_id" uuid,
  "diff_generation" integer NOT NULL,
  "key" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "body" text,
  "change_order" text[],
  "storage_url" text,
  PRIMARY KEY ("key", "release_id", "diff_generation"),
  CONSTRAINT "fk_resource_diffs_release" FOREIGN KEY ("release_id") REFERENCES "releases"("id")
);

-- -----------------------------------------------------------------------------
-- Agent Users and Auth
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "users" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "name" text,
  "hash" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_users_name" UNIQUE ("name")
);

CREATE INDEX IF NOT EXISTS "idx_users_deleted_at" ON "users" ("deleted_at");

CREATE TABLE IF NOT EXISTS "refresh_tokens" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "token_hash" text NOT NULL UNIQUE,
  "user_id" uuid NOT NULL,
  "cluster_id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "expires_at" timestamptz NOT NULL,
  "revoked_at" timestamptz,
  "parent_token_id" uuid,
  "replaced_by_token_id" uuid,
  "user_agent" text,
  "ip_address" text,
  CONSTRAINT "fk_refresh_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
  CONSTRAINT "fk_refresh_tokens_cluster" FOREIGN KEY ("cluster_id") REFERENCES "clusters"("id") ON DELETE CASCADE,
  CONSTRAINT "fk_parent_token" FOREIGN KEY ("parent_token_id") REFERENCES "refresh_tokens"("id") ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS "idx_refresh_tokens_hash" ON "refresh_tokens"("token_hash");
CREATE INDEX IF NOT EXISTS "idx_refresh_tokens_user_active" ON "refresh_tokens"("user_id", "expires_at") WHERE "revoked_at" IS NULL;
CREATE INDEX IF NOT EXISTS "idx_refresh_tokens_expires" ON "refresh_tokens"("expires_at") WHERE "revoked_at" IS NULL;

-- -----------------------------------------------------------------------------
-- UI Users and Sessions
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "ui_users" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deleted_at" timestamptz,
  "username" text NOT NULL,
  "password_hash" text NOT NULL,
  "roles" text[] NOT NULL DEFAULT '{}'::text[],
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_ui_users_username" UNIQUE ("username")
);

CREATE INDEX IF NOT EXISTS "idx_ui_users_deleted_at" ON "ui_users" ("deleted_at");

CREATE TABLE IF NOT EXISTS "ui_sessions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "expires_at" timestamptz NOT NULL,
  "revoked_at" timestamptz,
  "last_seen_at" timestamptz,
  "token_hash" text NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_ui_sessions_token_hash" UNIQUE ("token_hash"),
  CONSTRAINT "fk_ui_sessions_user" FOREIGN KEY ("user_id") REFERENCES "ui_users"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_ui_sessions_user_active" ON "ui_sessions" ("user_id", "expires_at") WHERE "revoked_at" IS NULL;
CREATE INDEX IF NOT EXISTS "idx_ui_sessions_expires" ON "ui_sessions" ("expires_at") WHERE "revoked_at" IS NULL;

-- -----------------------------------------------------------------------------
-- Errors
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "hive_errors" (
  "id" uuid DEFAULT gen_random_uuid(),
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deprecated_at" timestamptz,
  "cluster_id" uuid,
  "message" text,
  "is_deprecated" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_cluster_message" UNIQUE ("cluster_id", "message"),
  CONSTRAINT "fk_hive_errors_cluster" FOREIGN KEY ("cluster_id") REFERENCES "clusters"("id")
);

CREATE TABLE IF NOT EXISTS "release_errors" (
  "id" uuid DEFAULT gen_random_uuid(),
  "release_id" uuid,
  "created_at" timestamptz NOT NULL DEFAULT NOW(),
  "updated_at" timestamptz NOT NULL DEFAULT NOW(),
  "deprecated_at" timestamptz,
  "message" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "unique_release_message" UNIQUE ("release_id", "message"),
  CONSTRAINT "fk_release_errors_release" FOREIGN KEY ("release_id") REFERENCES "releases"("id")
);

-- -----------------------------------------------------------------------------
-- Helper Functions
-- -----------------------------------------------------------------------------

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

-- -----------------------------------------------------------------------------
-- Role Grants (if hive_user exists)
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hive_user') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public TO hive_user;
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO hive_user;
        GRANT CREATE ON SCHEMA public TO hive_user;

        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLES TO hive_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO hive_user;

        ALTER TABLE clusters OWNER TO hive_user;
        ALTER TABLE cluster_groups OWNER TO hive_user;
        ALTER TABLE namespaces OWNER TO hive_user;
        ALTER TABLE group_relationships OWNER TO hive_user;
        ALTER TABLE repos OWNER TO hive_user;
        ALTER TABLE repo_branches OWNER TO hive_user;
        ALTER TABLE repo_webhooks OWNER TO hive_user;
        ALTER TABLE repo_webhook_events OWNER TO hive_user;
        ALTER TABLE service_definitions OWNER TO hive_user;
        ALTER TABLE service_definition_cluster_group_relationships OWNER TO hive_user;
        ALTER TABLE service_versions OWNER TO hive_user;
        ALTER TABLE releases OWNER TO hive_user;
        ALTER TABLE resource_diffs OWNER TO hive_user;
        ALTER TABLE users OWNER TO hive_user;
        ALTER TABLE refresh_tokens OWNER TO hive_user;
        ALTER TABLE ui_users OWNER TO hive_user;
        ALTER TABLE ui_sessions OWNER TO hive_user;
        ALTER TABLE hive_errors OWNER TO hive_user;
        ALTER TABLE release_errors OWNER TO hive_user;
    END IF;
END $$;
