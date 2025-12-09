/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RepoProvider } from './RepoProvider';
/**
 * Generic paginated response wrapper for list endpoints
 */
export type PaginatedResponse_ServiceDefinitionData = {
    /**
     * The list of items for this page
     */
    data: Array<{
        branch: string;
        host: string;
        manifest_path_template?: string | null;
        name: string;
        org: string;
        provider: RepoProvider;
        repo: string;
        repo_branch_id: string;
        repo_id: string;
        service_definition_id: string;
        service_deleted_at?: string | null;
        source_branch_requirements?: string | null;
        web_base_url: string;
    }>;
    /**
     * Number of items returned in this response
     */
    limit: number;
    /**
     * Number of items skipped
     */
    offset: number;
    /**
     * Total number of items across all pages
     */
    total: number;
};

