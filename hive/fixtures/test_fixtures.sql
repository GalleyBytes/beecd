-- Test Fixtures: Simulating a Production Database with Dirty Data
-- This file creates hundreds of realistic entries to test against a "dirty" database

-- Create 50 clusters (mix of active, stale, and deleted)
DO $$
DECLARE
    cluster_ids uuid[] := ARRAY[]::uuid[];
    cluster_id uuid;
    i INT;
BEGIN
    FOR i IN 1..50 LOOP
        cluster_id := gen_random_uuid();
        cluster_ids := array_append(cluster_ids, cluster_id);
        
        INSERT INTO clusters (id, name, metadata, version, kubernetes_version, created_at, updated_at, last_check_in_at, deleted_at)
        VALUES (
            cluster_id,
            'prod-cluster-' || i,
            '{"region": "us-west-2", "env": "production"}',
            '1.' || (i % 5),
            '1.' || (25 + (i % 3)),
            NOW() - (i || ' days')::INTERVAL,
            NOW() - ((i / 2) || ' days')::INTERVAL,
            -- Some clusters haven't checked in for a while (stale)
            CASE WHEN i % 7 = 0 THEN NOW() - '30 days'::INTERVAL ELSE NOW() - (i || ' hours')::INTERVAL END,
            -- Some clusters are soft-deleted
            CASE WHEN i % 13 = 0 THEN NOW() - '5 days'::INTERVAL ELSE NULL END
        );
    END LOOP;

    -- Create 20 cluster groups
    FOR i IN 1..20 LOOP
        INSERT INTO cluster_groups (id, name, created_at, deleted_at)
        VALUES (
            gen_random_uuid(),
            'cluster-group-' || i,
            NOW() - (i || ' days')::INTERVAL,
            CASE WHEN i % 11 = 0 THEN NOW() - '2 days'::INTERVAL ELSE NULL END
        );
    END LOOP;

    -- Create group relationships (many-to-many)
    INSERT INTO group_relationships (cluster_id, cluster_group_id)
    SELECT 
        c.id as cluster_id,
        cg.id as cluster_group_id
    FROM clusters c
    CROSS JOIN cluster_groups cg
    WHERE c.deleted_at IS NULL 
        AND cg.deleted_at IS NULL
        AND (abs(hashtext(c.id::text) % 100)) < 30; -- 30% relationship probability

    -- Create namespaces for each cluster (multiple per cluster)
    FOR cluster_id IN SELECT id FROM clusters WHERE deleted_at IS NULL LOOP
        FOR i IN 1..8 LOOP
            INSERT INTO namespaces (id, name, cluster_id, created_at, deleted_at)
            VALUES (
                gen_random_uuid(),
                CASE 
                    WHEN i = 1 THEN 'default'
                    WHEN i = 2 THEN 'kube-system'
                    WHEN i = 3 THEN 'monitoring'
                    ELSE 'app-namespace-' || i
                END,
                cluster_id,
                NOW() - ((i * 5) || ' days')::INTERVAL,
                CASE WHEN i % 15 = 0 THEN NOW() - '1 day'::INTERVAL ELSE NULL END
            );
        END LOOP;
    END LOOP;
END $$;

-- Create 100 repos with branches
DO $$
DECLARE
    repo_ids uuid[] := ARRAY[]::uuid[];
    repo_id uuid;
    branch_id uuid;
    i INT;
    j INT;
BEGIN
    FOR i IN 1..100 LOOP
        repo_id := gen_random_uuid();
        repo_ids := array_append(repo_ids, repo_id);
        
        INSERT INTO repos (id, org, repo, manifest_store, script_store)
        VALUES (
            repo_id,
            CASE (i % 10)
                WHEN 0 THEN 'acme-corp'
                WHEN 1 THEN 'megacorp'
                WHEN 2 THEN 'startup-inc'
                WHEN 3 THEN 'enterprise-llc'
                WHEN 4 THEN 'bigtech'
                WHEN 5 THEN 'cloudnative'
                WHEN 6 THEN 'devops-team'
                WHEN 7 THEN 'platform-eng'
                WHEN 8 THEN 'sre-team'
                ELSE 'backend-team'
            END,
            'service-' || i,
            (i % 5 = 0), -- 20% manifest stores
            (i % 7 = 0)  -- ~14% script stores
        );

        -- Create 2-5 branches per repo
        FOR j IN 1..(2 + (i % 4)) LOOP
            INSERT INTO repo_branches (id, branch, repo_id)
            VALUES (
                gen_random_uuid(),
                CASE j
                    WHEN 1 THEN 'main'
                    WHEN 2 THEN 'develop'
                    WHEN 3 THEN 'staging'
                    WHEN 4 THEN 'release'
                    ELSE 'feature-' || j
                END,
                repo_id
            );
        END LOOP;
    END LOOP;
END $$;

-- Create build configs
DO $$
DECLARE
    branch_rec RECORD;
    i INT := 0;
BEGIN
    FOR branch_rec IN 
        SELECT id, repo_id FROM repo_branches 
        WHERE branch IN ('main', 'develop', 'staging')
        LIMIT 150
    LOOP
        i := i + 1;
        INSERT INTO build_configs (id, name, description, repo_branch_id, path, git_build_deps, created_at)
        VALUES (
            gen_random_uuid(),
            'build-config-' || i,
            'Automated build configuration for service',
            branch_rec.id,
            CASE (i % 4)
                WHEN 0 THEN '/docker/Dockerfile'
                WHEN 1 THEN '/build/Dockerfile'
                WHEN 2 THEN '/Dockerfile'
                ELSE '/container/Dockerfile'
            END,
            CASE 
                WHEN i % 3 = 0 THEN ARRAY['github.com/user/lib1', 'github.com/user/lib2']
                ELSE ARRAY[]::text[]
            END,
            NOW() - ((i * 2) || ' days')::INTERVAL
        );
    END LOOP;
END $$;

-- Create 200 build targets with various states
DO $$
DECLARE
    branch_rec RECORD;
    config_rec RECORD;
    i INT := 0;
BEGIN
    FOR branch_rec IN SELECT id FROM repo_branches LIMIT 200 LOOP
        i := i + 1;
        
        INSERT INTO service_definitions (
            id, name, repo_branch_id, source_branch_requirements, 
            build_config_id, created_at, deleted_at
        )
        VALUES (
            gen_random_uuid(),
            'api-service-' || i,
            branch_rec.id,
            CASE 
                WHEN i % 4 = 0 THEN '["main", "develop"]'
                WHEN i % 4 = 1 THEN '["main"]'
                ELSE '[]'
            END,
            (SELECT id FROM build_configs WHERE repo_branch_id = branch_rec.id LIMIT 1),
            NOW() - ((i * 3) || ' days')::INTERVAL,
            CASE WHEN i % 17 = 0 THEN NOW() - '3 days'::INTERVAL ELSE NULL END
        );
    END LOOP;
END $$;

-- Create service definition to cluster group relationships
INSERT INTO service_definition_cluster_group_relationships (service_definition_id, cluster_group_id)
SELECT 
    sd.id as service_definition_id,
    cg.id as cluster_group_id
FROM service_definitions sd
CROSS JOIN cluster_groups cg
WHERE sd.deleted_at IS NULL 
    AND cg.deleted_at IS NULL
    AND (abs(hashtext(sd.id::text) % 100)) < 25; -- 25% relationship probability

-- Create 500 releases with various states
DO $$
DECLARE
    namespace_rec RECORD;
    branch_rec RECORD;
    i INT := 0;
    release_id uuid;
    service_id uuid;
BEGIN
    FOR namespace_rec IN SELECT id, cluster_id FROM namespaces WHERE deleted_at IS NULL LIMIT 100 LOOP
        FOR i IN 1..5 LOOP
            release_id := gen_random_uuid();
            service_id := gen_random_uuid();
            
            INSERT INTO releases (
                id, namespace_id, name, path, repo_branch_id,
                hash, version, git_sha, service_id,
                approved_by, approved_at,
                started_first_install_at, completed_first_install_at,
                started_update_install_at, completed_update_install_at,
                marked_for_deletion_at, completed_delete_at,
                deprecated_at, diff_generation,
                created_at, updated_at
            )
            SELECT
                release_id,
                namespace_rec.id,
                'release-' || i || '-' || (abs(hashtext(namespace_rec.id::text)) % 1000),
                '/manifests/service-' || i || '.yaml',
                rb.id,
                substring(encode(gen_random_bytes(20), 'hex') from 1 for 40),
                'v1.' || (i % 20) || '.' || (abs(hashtext(namespace_rec.id::text)) % 100),
                substring(encode(gen_random_bytes(20), 'hex') from 1 for 40),
                service_id,
                CASE WHEN i % 3 = 0 THEN 'user' || (i % 10) || '@example.com' ELSE NULL END,
                CASE WHEN i % 3 = 0 THEN NOW() - ((i * 2) || ' hours')::INTERVAL ELSE NULL END,
                -- First install states
                CASE WHEN i % 5 != 4 THEN NOW() - ((i * 5) || ' hours')::INTERVAL ELSE NULL END,
                CASE WHEN i % 5 != 4 THEN NOW() - ((i * 4) || ' hours')::INTERVAL ELSE NULL END,
                -- Update states (some in progress)
                CASE WHEN i % 4 = 0 THEN NOW() - ((i) || ' hours')::INTERVAL ELSE NULL END,
                CASE WHEN i % 4 = 0 AND i % 8 != 0 THEN NOW() - ((i / 2) || ' hours')::INTERVAL ELSE NULL END,
                -- Delete states (some marked for deletion)
                CASE WHEN i % 19 = 0 THEN NOW() - '1 hour'::INTERVAL ELSE NULL END,
                CASE WHEN i % 23 = 0 THEN NOW() - '30 minutes'::INTERVAL ELSE NULL END,
                -- Deprecated releases
                CASE WHEN i = 1 THEN NOW() - '2 days'::INTERVAL ELSE NULL END,
                (i % 5), -- diff generation
                NOW() - ((i * 8) || ' hours')::INTERVAL,
                NOW() - ((i * 2) || ' hours')::INTERVAL
            FROM repo_branches rb
            LIMIT 1 OFFSET (abs(hashtext(namespace_rec.id::text)) % 200);
        END LOOP;
    END LOOP;
END $$;

-- Create resource diffs for some releases
DO $$
DECLARE
    release_rec RECORD;
    i INT;
BEGIN
    FOR release_rec IN SELECT id, diff_generation FROM releases WHERE diff_generation > 0 LIMIT 200 LOOP
        FOR i IN 0..release_rec.diff_generation LOOP
            INSERT INTO resource_diffs (release_id, diff_generation, key, body, change_order)
            VALUES (
                release_rec.id,
                i,
                'manifest-' || i || '.yaml',
                '{"kind": "Deployment", "metadata": {"name": "test-app-' || i || '"}}',
                ARRAY['CREATE', 'UPDATE']
            );
        END LOOP;
    END LOOP;
END $$;

-- Create users (some deleted)
DO $$
DECLARE
    i INT;
BEGIN
    FOR i IN 1..30 LOOP
        INSERT INTO users (id, name, hash, created_at, deleted_at)
        VALUES (
            gen_random_uuid(),
            'user' || i || '@example.com',
            '$2a$10$' || substring(encode(gen_random_bytes(40), 'hex') from 1 for 53), -- bcrypt hash format
            NOW() - ((i * 10) || ' days')::INTERVAL,
            CASE WHEN i % 9 = 0 THEN NOW() - '5 days'::INTERVAL ELSE NULL END
        );
    END LOOP;
END $$;

-- Create hive errors (some deprecated)
DO $$
DECLARE
    cluster_rec RECORD;
    i INT;
BEGIN
    FOR cluster_rec IN SELECT id FROM clusters WHERE deleted_at IS NULL LIMIT 30 LOOP
        FOR i IN 1..3 LOOP
            INSERT INTO hive_errors (id, cluster_id, message, is_deprecated, deprecated_at, created_at)
            VALUES (
                gen_random_uuid(),
                cluster_rec.id,
                CASE (i % 5)
                    WHEN 0 THEN 'Failed to connect to API server: connection timeout'
                    WHEN 1 THEN 'Namespace not found: app-namespace-1'
                    WHEN 2 THEN 'Insufficient permissions to create deployment'
                    WHEN 3 THEN 'ImagePullBackOff: registry authentication failed'
                    ELSE 'Pod CrashLoopBackOff: application startup failed'
                END,
                (i % 3 = 0),
                CASE WHEN i % 3 = 0 THEN NOW() - '1 day'::INTERVAL ELSE NULL END,
                NOW() - ((i * 4) || ' hours')::INTERVAL
            );
        END LOOP;
    END LOOP;
END $$;

-- Create release errors
DO $$
DECLARE
    release_rec RECORD;
    i INT;
BEGIN
    FOR release_rec IN SELECT id FROM releases WHERE completed_first_install_at IS NULL LIMIT 50 LOOP
        FOR i IN 1..2 LOOP
            INSERT INTO release_errors (id, release_id, message, deprecated_at, created_at)
            VALUES (
                gen_random_uuid(),
                release_rec.id,
                CASE (i % 4)
                    WHEN 0 THEN 'Deployment failed: image not found'
                    WHEN 1 THEN 'ConfigMap validation error: missing required key'
                    WHEN 2 THEN 'Service port conflict: port 8080 already in use'
                    ELSE 'Resource quota exceeded: cannot allocate additional pods'
                END,
                CASE WHEN i = 1 THEN NOW() - '2 hours'::INTERVAL ELSE NULL END,
                NOW() - ((i) || ' hours')::INTERVAL
            );
        END LOOP;
    END LOOP;
END $$;

-- Create some edge case data for testing

-- Duplicate-like data (but not violating unique constraints)
INSERT INTO clusters (id, name, metadata, version, kubernetes_version)
VALUES 
    (gen_random_uuid(), 'test-cluster', '{}', '1.0', '1.28'),
    (gen_random_uuid(), 'test-cluster-2', '{}', '1.0', '1.28'),
    (gen_random_uuid(), 'TEST-CLUSTER-3', '{}', '1.0', '1.28'); -- Case sensitivity

-- Clusters with very old check-ins (zombie clusters)
INSERT INTO clusters (id, name, metadata, version, kubernetes_version, last_check_in_at)
VALUES 
    (gen_random_uuid(), 'zombie-cluster-1', '{}', '1.0', '1.28', NOW() - '180 days'::INTERVAL),
    (gen_random_uuid(), 'zombie-cluster-2', '{}', '1.0', '1.28', NOW() - '365 days'::INTERVAL);

-- Empty/minimal data
INSERT INTO clusters (id, name, metadata, version, kubernetes_version)
VALUES (gen_random_uuid(), '', '{}', '', '');

INSERT INTO repos (id, org, repo)
VALUES (gen_random_uuid(), '', 'empty-org-repo');

-- Very long names (testing boundaries)
INSERT INTO cluster_groups (id, name)
VALUES (gen_random_uuid(), repeat('a', 255));

-- Special characters in names
INSERT INTO repos (id, org, repo)
VALUES 
    (gen_random_uuid(), 'org-with-dashes', 'repo-with-dashes'),
    (gen_random_uuid(), 'org_with_underscores', 'repo_with_underscores'),
    (gen_random_uuid(), 'org.with.dots', 'repo.with.dots');

-- Summary stats
DO $$
BEGIN
    RAISE NOTICE '=== Test Fixtures Loaded ===';
    RAISE NOTICE 'Clusters: %', (SELECT COUNT(*) FROM clusters);
    RAISE NOTICE 'Cluster Groups: %', (SELECT COUNT(*) FROM cluster_groups);
    RAISE NOTICE 'Namespaces: %', (SELECT COUNT(*) FROM namespaces);
    RAISE NOTICE 'Repos: %', (SELECT COUNT(*) FROM repos);
    RAISE NOTICE 'Branches: %', (SELECT COUNT(*) FROM repo_branches);
    RAISE NOTICE 'Build Configs: %', (SELECT COUNT(*) FROM build_configs);
    RAISE NOTICE 'Service Definitions: %', (SELECT COUNT(*) FROM service_definitions);
    RAISE NOTICE 'Releases: %', (SELECT COUNT(*) FROM releases);
    RAISE NOTICE 'Resource Diffs: %', (SELECT COUNT(*) FROM resource_diffs);
    RAISE NOTICE 'Users: %', (SELECT COUNT(*) FROM users);
    RAISE NOTICE 'Hive Errors: %', (SELECT COUNT(*) FROM hive_errors);
    RAISE NOTICE 'Release Errors: %', (SELECT COUNT(*) FROM release_errors);
    RAISE NOTICE '===========================';
END $$;
