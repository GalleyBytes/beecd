/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RepoProvider } from './RepoProvider';
export type ReleaseData = {
    api_base_url: string;
    approved_at?: string | null;
    approved_by?: string | null;
    branch: string;
    cluster_groups: string;
    cluster_id: string;
    cluster_name: string;
    completed_delete_at?: string | null;
    completed_first_install_at?: string | null;
    completed_update_install_at?: string | null;
    created_at?: string | null;
    deleted_at?: string | null;
    deprecated_at?: string | null;
    diff_generation: number;
    diff_namespace_id?: string | null;
    diff_service_id?: string | null;
    failed_delete_at?: string | null;
    failed_first_install_at?: string | null;
    failed_update_install_at?: string | null;
    git_sha: string;
    hash: string;
    host: string;
    id: string;
    is_diff?: boolean | null;
    last_diff_at?: string | null;
    last_sync_at?: string | null;
    manifest_path_template?: string | null;
    manually_selected_at?: string | null;
    name: string;
    namespace: string;
    namespace_id: string;
    org: string;
    path: string;
    pinned_at?: string | null;
    pinned_by?: string | null;
    previous_installed_hash?: string | null;
    provider: RepoProvider;
    repo: string;
    repo_branch_id: string;
    repo_id: string;
    service_definition_id: string;
    service_id?: string | null;
    started_delete_at?: string | null;
    started_first_install_at?: string | null;
    started_update_install_at?: string | null;
    total_errors: number;
    unapproved_at?: string | null;
    unapproved_by?: string | null;
    unapproved_reason?: string | null;
    updated_at?: string | null;
    version: string;
    web_base_url: string;
};

