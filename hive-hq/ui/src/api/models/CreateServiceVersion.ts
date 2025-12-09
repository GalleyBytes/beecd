/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for creating a new service version
 */
export type CreateServiceVersion = {
    /**
     * Full git commit SHA
     */
    git_sha: string;
    /**
     * Content hash of the rendered manifest
     */
    hash: string;
    /**
     * The namespace where this version can be deployed
     */
    namespace_id: string;
    /**
     * Path to manifest in repo (e.g., "deploy/production")
     */
    path: string;
    /**
     * The service definition ID this version belongs to
     */
    service_definition_id: string;
    /**
     * How this version was registered: 'api', 'git_watcher', 'webhook'
     */
    source?: string;
    /**
     * Additional source-specific metadata
     */
    source_metadata?: any;
    /**
     * Semantic version or tag (e.g., "1.2.3", "v1.0.0")
     */
    version: string;
};

