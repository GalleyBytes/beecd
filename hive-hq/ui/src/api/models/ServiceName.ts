/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ServiceName = {
    /**
     * Path template for manifest files in the git repository.
     * Supports placeholders: {cluster}, {namespace}, {service}
     * If ends with .yaml/.yml, watches a single file.
     * Otherwise, watches all *.yaml files in the directory.
     */
    manifest_path_template?: string | null;
    name: string;
};

