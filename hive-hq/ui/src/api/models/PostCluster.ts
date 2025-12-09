/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PostCluster = {
    /**
     * Context for manifest generation (namespace, grpc_address host:port, grpc_tls, image)
     */
    context?: any;
    name: string;
    /**
     * If true and user already exists, regenerate the secret
     */
    regenerate_secret?: boolean | null;
};

