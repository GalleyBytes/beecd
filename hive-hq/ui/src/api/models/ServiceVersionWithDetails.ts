/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RepoProvider } from './RepoProvider';
/**
 * Extended service version data with joined service and repo information
 */
export type ServiceVersionWithDetails = {
    branch: string;
    cluster_name: string;
    created_at: string;
    deprecated_at?: string | null;
    git_sha: string;
    git_sha_short?: string | null;
    hash: string;
    host: string;
    id: string;
    namespace_id: string;
    namespace_name: string;
    org: string;
    path: string;
    provider: RepoProvider;
    repo: string;
    service_definition_id: string;
    service_name: string;
    source: string;
    updated_at: string;
    version: string;
    web_base_url: string;
};

