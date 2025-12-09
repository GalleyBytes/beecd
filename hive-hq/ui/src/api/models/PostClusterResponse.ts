/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Cluster } from './Cluster';
/**
 * Response when creating a cluster
 */
export type PostClusterResponse = {
    cluster: Cluster;
    /**
     * The generated manifest.
     */
    manifest?: string | null;
    /**
     * True if the manifest is rendered with a placeholder secret (server does not store the real secret).
     */
    manifest_is_placeholder?: boolean;
    /**
     * Whether the secret was regenerated
     */
    secret_regenerated: boolean;
    /**
     * Whether a user with matching name already existed
     */
    user_existed: boolean;
};

