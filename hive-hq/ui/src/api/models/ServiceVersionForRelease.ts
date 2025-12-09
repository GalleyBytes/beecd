/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Service version data for release version selection UI
 * Includes deployment history and pinning info
 */
export type ServiceVersionForRelease = {
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
};

