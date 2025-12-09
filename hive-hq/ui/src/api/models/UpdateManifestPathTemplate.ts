/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for updating a service definition's manifest path template
 */
export type UpdateManifestPathTemplate = {
    /**
     * Path template with {service}, {cluster}, {namespace} placeholders
     * Example: "manifests/{cluster}/{namespace}/{service}"
     */
    manifest_path_template: string;
};

