/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Generic paginated response wrapper for list endpoints
 */
export type PaginatedResponse_ClusterGroupData = {
    /**
     * The list of items for this page
     */
    data: Array<{
        id: string;
        name: string;
        priority: number;
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

