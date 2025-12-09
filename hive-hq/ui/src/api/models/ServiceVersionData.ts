/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Service version data - represents a deployable version of a service
 * This replaces the external aversion database dependency
 */
export type ServiceVersionData = {
    created_at: string;
    deprecated_at?: string | null;
    deprecated_by?: string | null;
    deprecated_reason?: string | null;
    git_sha: string;
    git_sha_short?: string | null;
    hash: string;
    id: string;
    namespace_id: string;
    path: string;
    service_definition_id: string;
    source: string;
    source_metadata?: any;
    updated_at: string;
    version: string;
};

