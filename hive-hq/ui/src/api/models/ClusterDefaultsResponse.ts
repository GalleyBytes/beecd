/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ClusterDefaultsResponse = {
    /**
     * Default agent container image
     */
    agent_image?: string | null;
    /**
     * Default Hive gRPC address in host:port form (no scheme)
     */
    grpc_address?: string | null;
    /**
     * Whether TLS should be used when constructing the gRPC URI from host:port
     */
    grpc_tls?: boolean | null;
};

