/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RepoProvider } from './RepoProvider';
/**
 * Generic paginated response wrapper for list endpoints
 */
export type PaginatedResponse_RepoData = {
    /**
     * The list of items for this page
     */
    data: Array<{
        api_base_url: string;
        host: string;
        id: string;
        org: string;
        provider: RepoProvider;
        repo: string;
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

