/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Generic paginated response wrapper for list endpoints
 */
export type PaginatedResponse_Cluster = {
    /**
     * The list of items for this page
     */
    data: Array<{
        id: string;
        kubernetes_version?: string | null;
        metadata?: string | null;
        name: string;
        version?: string | null;
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

