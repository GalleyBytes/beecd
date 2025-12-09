/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Generic paginated response wrapper for list endpoints
 */
export type PaginatedResponse_ServiceVersionForRelease = {
    /**
     * The list of items for this page
     */
    data: Array<{
        created_at: string;
        deprecated_at?: string | null;
        git_sha: string;
        git_sha_short?: string | null;
        hash: string;
        id: string;
        is_current: boolean;
        last_deployed_at?: string | null;
        namespace_id: string;
        path: string;
        pinned_at?: string | null;
        pinned_by?: string | null;
        service_definition_id: string;
        source: string;
        version: string;
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

