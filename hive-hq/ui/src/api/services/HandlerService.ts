/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddClusterGroupInput } from '../models/AddClusterGroupInput';
import type { AdditionalInstallation } from '../models/AdditionalInstallation';
import type { AutosyncData } from '../models/AutosyncData';
import type { Cluster } from '../models/Cluster';
import type { ClusterClusterGroups } from '../models/ClusterClusterGroups';
import type { ClusterDefaultsResponse } from '../models/ClusterDefaultsResponse';
import type { ClusterGroupClusterAssociation } from '../models/ClusterGroupClusterAssociation';
import type { ClusterGroupData } from '../models/ClusterGroupData';
import type { ClusterGroupServices } from '../models/ClusterGroupServices';
import type { ClusterNamespaceServicesData } from '../models/ClusterNamespaceServicesData';
import type { CreateServiceVersion } from '../models/CreateServiceVersion';
import type { DeleteRepoWebhookRequest } from '../models/DeleteRepoWebhookRequest';
import type { DeprecateServiceVersion } from '../models/DeprecateServiceVersion';
import type { DiffDataWithBody } from '../models/DiffDataWithBody';
import type { ErrorCount } from '../models/ErrorCount';
import type { Heartbeat } from '../models/Heartbeat';
import type { HiveError } from '../models/HiveError';
import type { NamespaceData } from '../models/NamespaceData';
import type { PaginatedResponse_Cluster } from '../models/PaginatedResponse_Cluster';
import type { PaginatedResponse_ClusterGroupData } from '../models/PaginatedResponse_ClusterGroupData';
import type { PaginatedResponse_RepoData } from '../models/PaginatedResponse_RepoData';
import type { PaginatedResponse_ServiceDefinitionData } from '../models/PaginatedResponse_ServiceDefinitionData';
import type { PaginatedResponse_ServiceVersionForRelease } from '../models/PaginatedResponse_ServiceVersionForRelease';
import type { PathTemplateValidation } from '../models/PathTemplateValidation';
import type { PendingReleases } from '../models/PendingReleases';
import type { PinServiceVersion } from '../models/PinServiceVersion';
import type { PostAdditionalInstallation } from '../models/PostAdditionalInstallation';
import type { PostBranch } from '../models/PostBranch';
import type { PostCluster } from '../models/PostCluster';
import type { PostClusterResponse } from '../models/PostClusterResponse';
import type { PostInitReleases } from '../models/PostInitReleases';
import type { PostNamespaceNames } from '../models/PostNamespaceNames';
import type { PostRepo } from '../models/PostRepo';
import type { PostSubscriptions } from '../models/PostSubscriptions';
import type { PostUser } from '../models/PostUser';
import type { PutApprovals } from '../models/PutApprovals';
import type { PutClusterGroup } from '../models/PutClusterGroup';
import type { PutServiceData } from '../models/PutServiceData';
import type { RegisterRepoWebhookRequest } from '../models/RegisterRepoWebhookRequest';
import type { RegisterRepoWebhookResponse } from '../models/RegisterRepoWebhookResponse';
import type { ReleaseCandidate } from '../models/ReleaseCandidate';
import type { ReleaseStatus } from '../models/ReleaseStatus';
import type { RepoBranches } from '../models/RepoBranches';
import type { RepoData } from '../models/RepoData';
import type { RepoWebhookData } from '../models/RepoWebhookData';
import type { RepoWebhookEvent } from '../models/RepoWebhookEvent';
import type { ServiceAutosyncBranches } from '../models/ServiceAutosyncBranches';
import type { ServiceDefinitionData } from '../models/ServiceDefinitionData';
import type { ServiceName } from '../models/ServiceName';
import type { ServiceVersionData } from '../models/ServiceVersionData';
import type { ServiceVersionWithDetails } from '../models/ServiceVersionWithDetails';
import type { UpdateManifestPathTemplate } from '../models/UpdateManifestPathTemplate';
import type { UserData } from '../models/UserData';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class HandlerService {
    /**
     * Update a list of releases for approval
     * @returns ReleaseCandidate Returns a list of available releases that can be mass approved
     * @throws ApiError
     */
    public static putApprovals({
        requestBody,
    }: {
        requestBody: PutApprovals,
    }): CancelablePromise<Array<ReleaseCandidate>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/approvals',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when json data is missing`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Update a list of releases for unapproval (ie pause drift management)
     * @returns void
     * @throws ApiError
     */
    public static putUnapprovals({
        requestBody,
    }: {
        requestBody: PutApprovals,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/approvals/unapprove',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when json data is missing`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get namespaces for a given cluster by name (aversion service endpoint)
     * @returns NamespaceData
     * @throws ApiError
     */
    public static getNamespacesViaClusterName({
        clusterName,
    }: {
        clusterName: string,
    }): CancelablePromise<Array<NamespaceData>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/aversion/clusters/{cluster_name}/namespaces',
            path: {
                'cluster_name': clusterName,
            },
            errors: {
                401: `Access token is missing or invalid`,
                403: `Requires aversion or admin role`,
                500: `Fails when cluster name is invalid or db connection issues`,
            },
        });
    }
    /**
     * Gets a list of service_definitions that are configured for the branch
     * @returns ServiceDefinitionData Returns a list of service_definitions configured for the branch
     * @throws ApiError
     */
    public static getBranchServiceDefinitions({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ServiceDefinitionData>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/branches/{id}/service-definitions',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Add a service to a specific branch via id
     * @returns void
     * @throws ApiError
     */
    public static postBranchService({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: ServiceName,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/branches/{id}/service-definitions',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Given a branch id, get a list other branches with "sync" configuration data
     * @returns AutosyncData Returns a list of sync configuration data for a specific branch
     * @throws ApiError
     */
    public static getAutosyncData({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<AutosyncData>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/branches/{id}/service-definitions/autosync',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Update a branch to by synced with other branches
     * @returns void
     * @throws ApiError
     */
    public static putBranchAutosync({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: ServiceAutosyncBranches,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/branches/{id}/service-definitions/autosync',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get default values for cluster creation/manifest generation.
     * Values come from environment variables configured on the API:
     * - HIVE_DEFAULT_GRPC_SERVER (may be scheme or host:port)
     * - AGENT_DEFAULT_IMAGE
     * @returns ClusterDefaultsResponse Returns configured defaults for cluster creation
     * @throws ApiError
     */
    public static getClusterDefaults(): CancelablePromise<ClusterDefaultsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-defaults',
        });
    }
    /**
     * Get a list of all cluster groups
     * @returns PaginatedResponse_ClusterGroupData Returns a paginated list of cluster groups
     * @throws ApiError
     */
    public static getClusterGroups({
        limit,
        offset,
    }: {
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<PaginatedResponse_ClusterGroupData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-groups',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when no rows are found in database`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Adds a new cluster group
     * @returns void
     * @throws ApiError
     */
    public static addClusterGroups({
        requestBody,
    }: {
        requestBody: AddClusterGroupInput,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/cluster-groups',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when post data is empty`,
                500: `Fails when cluster_group name is not found or db connection issues`,
            },
        });
    }
    /**
     * Get details of cluster group
     * @returns ClusterGroupData Returns details for a single cluster group
     * @throws ApiError
     */
    public static getClusterGroup({
        id,
    }: {
        id: string,
    }): CancelablePromise<ClusterGroupData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-groups/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Update details of cluster group
     * @returns void
     * @throws ApiError
     */
    public static putClusterGroup({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PutClusterGroup,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/cluster-groups/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Delete a cluster group by id
     * @returns void
     * @throws ApiError
     */
    public static deleteClusterGroup({
        id,
    }: {
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/cluster-groups/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Gets a list of clusters associated with a cluster-group
     * @returns ClusterGroupClusterAssociation Returns a list of clusters associated with a cluster-group via id
     * @throws ApiError
     */
    public static getClusterGroupClusterAssociation({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ClusterGroupClusterAssociation>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-groups/{id}/clusters',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Attach a cluster or a list of clusters to a cluster group
     * @returns void
     * @throws ApiError
     */
    public static postSubscribeClusters({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostSubscriptions,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/cluster-groups/{id}/clusters',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                422: `Fails when adding a cluster to cluster-group fails validation`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get a list of service_definitions that have relationships to a particular cluster-group
     * @returns ClusterGroupServices Returns a list of service_definitions related to a cluster group
     * @throws ApiError
     */
    public static getClusterGroupServiceDefinitions({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ClusterGroupServices>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-groups/{id}/service-definitions',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Attach a service or a list of service_definitions to a cluster group
     * @returns void
     * @throws ApiError
     */
    public static putSubscribeServiceDefinitions({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostSubscriptions,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/cluster-groups/{id}/service-definitions',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                422: `Fails when adding a service to cluster-group fails validation`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Attach a service or a list of service_definitions to a cluster group
     * @returns void
     * @throws ApiError
     */
    public static postSubscribeServiceDefinitions({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostSubscriptions,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/cluster-groups/{id}/service-definitions',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                422: `Fails when adding a service to cluster-group fails validation`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Remove the relationship between a cluster-group and a service
     * @returns void
     * @throws ApiError
     */
    public static deleteServiceDefinitionRelationship({
        id,
        serviceDefinitionId,
    }: {
        id: string,
        serviceDefinitionId: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/cluster-groups/{id}/service-definitions/{service_definition_id}',
            path: {
                'id': id,
                'service_definition_id': serviceDefinitionId,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when relationship not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get a list of service data not associated with a particular cluster group via id
     * @returns ServiceDefinitionData Returns a list of all service data not associated with a cluster group
     * @throws ApiError
     */
    public static getUnassociatedServiceDefinitionsForClusterGroup({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ServiceDefinitionData>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/cluster-groups/{id}/unassociated-service-definitions',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Get a list of all non-deleted clusters
     * @returns PaginatedResponse_Cluster Returns a paginated list of all non-deleted clusters
     * @throws ApiError
     */
    public static getClusters({
        limit,
        offset,
    }: {
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<PaginatedResponse_Cluster> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Create a new cluster
     * Creates a cluster and optionally creates/updates the associated agent user.
     * If a user with the same name already exists and `regenerate_secret` is not set,
     * returns user_existed=true without generating a manifest.
     * If `regenerate_secret` is true, updates the existing user's secret and returns a new manifest.
     * @returns PostClusterResponse Returns cluster data with manifest info
     * @throws ApiError
     */
    public static postCluster({
        requestBody,
    }: {
        requestBody: PostCluster,
    }): CancelablePromise<PostClusterResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/clusters',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                409: `Fails on duplicate cluster name`,
                422: `Fails when post data is invalid`,
                424: `Fails when manifest could not be generated`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Get cluster data via id
     * @returns Cluster Successful cluster query
     * @throws ApiError
     */
    public static getCluster({
        id,
    }: {
        id: string,
    }): CancelablePromise<Cluster> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Delete a cluster by id
     * @returns void
     * @throws ApiError
     */
    public static deleteCluster({
        id,
    }: {
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/clusters/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Gets a list of current errors produced for the agent given the cluster id
     * @returns HiveError Returns a list errors produced by the hive agent
     * @throws ApiError
     */
    public static getHiveAgentErrors({
        id,
    }: {
        id: string,
    }): CancelablePromise<Array<HiveError>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}/errors',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get a list of cluster groups for a particular cluster by id
     * @returns ClusterClusterGroups Returns a list of cluster groups for the given cluster
     * @throws ApiError
     */
    public static getClusterClusterGroups({
        id,
    }: {
        id: string,
    }): CancelablePromise<Array<ClusterClusterGroups>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}/groups',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when row not found in database`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Delete a cluster group/cluster relationship
     * @returns void
     * @throws ApiError
     */
    public static deleteGroupRelationship({
        id,
        clusterGroupId,
    }: {
        id: string,
        clusterGroupId: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/clusters/{id}/groups/{cluster_group_id}',
            path: {
                'id': id,
                'cluster_group_id': clusterGroupId,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when row not found in database`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Gets the last heartbeat information for an agent given the cluster id
     * @returns Heartbeat Returns the last heartbeat produced by the hive agent
     * @throws ApiError
     */
    public static getHiveAgentHeartbeat({
        id,
    }: {
        id: string,
    }): CancelablePromise<Heartbeat> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}/heartbeat',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get namespaces for a given cluster by id
     * @returns ClusterNamespaceServicesData
     * @throws ApiError
     */
    public static getClusterNamespaces({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ClusterNamespaceServicesData>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}/namespaces',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when row not found in database`,
                500: `Fails when id is invalid or db connection issues`,
            },
        });
    }
    /**
     * Add a new namespace to a cluster via id
     * @returns void
     * @throws ApiError
     */
    public static postCreateClusterNamespaces({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostNamespaceNames,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/clusters/{id}/namespaces',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when json data is missing`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets a list of resource status for given cluster id
     * @returns ReleaseStatus Returns a list of resource statuses
     * @throws ApiError
     */
    public static getReleaseStatus({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ReleaseStatus>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/clusters/{id}/releases',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get a count of errors for each cluster
     * @returns ErrorCount Successful deletion of cluster
     * @throws ApiError
     */
    public static getErrorCount({
        limit,
        offset,
    }: {
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ErrorCount>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/count/errors',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Gets a list of release details for a release by name in a namespace
     * @returns ReleaseStatus Returns a list of releases
     * @throws ApiError
     */
    public static getNamespaceReleases({
        id,
        releaseName,
        limit,
        offset,
    }: {
        id: string,
        releaseName: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<ReleaseStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/namespaces/{id}/release/{release_name}',
            path: {
                'id': id,
                'release_name': releaseName,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets details for a specific release
     * @returns ReleaseStatus Returns details of a release
     * @throws ApiError
     */
    public static getNamespaceReleaseInfo({
        id,
        releaseName,
    }: {
        id: string,
        releaseName: string,
    }): CancelablePromise<ReleaseStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/namespaces/{id}/release/{release_name}/current',
            path: {
                'id': id,
                'release_name': releaseName,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Removes the manually selected field to revert back to latest release (default)
     * Going back to the latest is essentially re-enabling drift to ensure this service is up-to-date with
     * services that share the same build target.
     * @returns void
     * @throws ApiError
     */
    public static putRestoreLatestRelease({
        id,
        releaseName,
    }: {
        id: string,
        releaseName: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/namespaces/{id}/release/{release_name}/latest',
            path: {
                'id': id,
                'release_name': releaseName,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `No changes were required, no releases matching query were found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets all service versions available for a release, with deployment history
     * This shows all versions that can be selected, including whether they've been deployed
     * @returns PaginatedResponse_ServiceVersionForRelease Returns a paginated list of service versions for this release
     * @throws ApiError
     */
    public static getReleaseServiceVersions({
        id,
        releaseName,
        deployedOnly,
        limit,
        offset,
    }: {
        /**
         * Namespace UUID
         */
        id: string,
        /**
         * Release name
         */
        releaseName: string,
        /**
         * Only show versions that have been deployed (default: false)
         */
        deployedOnly?: boolean,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<PaginatedResponse_ServiceVersionForRelease> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/namespaces/{id}/release/{release_name}/versions',
            path: {
                'id': id,
                'release_name': releaseName,
            },
            query: {
                'deployed_only': deployedOnly,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Remove a service name from a namespace
     * @returns void
     * @throws ApiError
     */
    public static deleteServiceFromNamespace({
        id,
        name,
    }: {
        id: string,
        name: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/namespaces/{id}/service-name/{name}',
            path: {
                'id': id,
                'name': name,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Fails when relationship not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get all service versions for a namespace
     * @returns ServiceVersionWithDetails Returns a list of service versions
     * @throws ApiError
     */
    public static getNamespaceServiceVersions({
        namespaceId,
        limit,
        offset,
    }: {
        /**
         * Namespace UUID
         */
        namespaceId: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ServiceVersionWithDetails>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/namespaces/{namespace_id}/service-versions',
            path: {
                'namespace_id': namespaceId,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Adds or reinstates batch of releases to clusters
     * Similar to "/api/releases/namespaces/{id}/init", but handles multiple service_definitions and multiple namespaces in the same query.
     * Also on success returns 204 instead.
     * @returns void
     * @throws ApiError
     */
    public static postAdditionalInstallations({
        requestBody,
    }: {
        requestBody: Array<PostAdditionalInstallation>,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/releases/init-many',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when post data is empty`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Adds or reinstates a release to a cluster, and then finds similar clusters
     * @returns AdditionalInstallation Returns a list of similar clusters
     * @throws ApiError
     */
    public static postInitRelease({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostInitReleases,
    }): CancelablePromise<Array<AdditionalInstallation>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/releases/namespaces/{id}/init',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Gets a list of pending all pending releases
     * @returns PendingReleases Returns a list of all pending releases
     * @throws ApiError
     */
    public static getPendingReleases(): CancelablePromise<Array<PendingReleases>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/releases/pending',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets a list of resource diffs per release given a diff_generation
     * @returns DiffDataWithBody Returns a list of resource diff data for release via id
     * @throws ApiError
     */
    public static getResourceDiffsForRelease({
        id,
        diffGeneration,
        limit,
        offset,
    }: {
        id: string,
        diffGeneration: number,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<DiffDataWithBody>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/releases/{id}/diff/{diff_generation}',
            path: {
                'id': id,
                'diff_generation': diffGeneration,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets a list of the latest errors produced by a specific release
     * @returns HiveError Returns a list of the latest errors produced by a specific release
     * @throws ApiError
     */
    public static getReleaseErrors({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<HiveError>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/releases/{id}/errors',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Marks a release as exact instead of using latest
     * @returns void
     * @throws ApiError
     */
    public static putReleaseSelection({
        id,
    }: {
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/releases/{id}/select',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets a list of all repos
     * @returns PaginatedResponse_RepoData Returns paginated repos data
     * @throws ApiError
     */
    public static getRepos({
        limit,
        offset,
    }: {
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<PaginatedResponse_RepoData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Adds a new repo
     * @returns RepoData Returns repo data on success
     * @throws ApiError
     */
    public static postRepo({
        requestBody,
    }: {
        requestBody: PostRepo,
    }): CancelablePromise<RepoData> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/repos',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets repo data for specific repo via id
     * @returns RepoData Returns repo data
     * @throws ApiError
     */
    public static getRepo({
        id,
    }: {
        id: string,
    }): CancelablePromise<RepoData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Gets branches for a specific repo via id
     * @returns RepoBranches Returns branches data
     * @throws ApiError
     */
    public static getBranches({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<RepoBranches>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos/{id}/branches',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Add a new branch to a specific repo via id
     * @returns void
     * @throws ApiError
     */
    public static postBranch({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PostBranch,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/repos/{id}/branches',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Fails when json data is missing`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Return a list of service_definitions in common for all branches in a repo
     * @returns ServiceName Returns a list of service_definitions in common for all branches in a repo
     * @throws ApiError
     */
    public static getRepoServiceDefinitions({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ServiceName>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos/{id}/service-definitions',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Adds a service is common across all branches of a repo
     * @returns void
     * @throws ApiError
     */
    public static postGlobalRepoService({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: ServiceName,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/repos/{id}/service-definitions',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                406: `Failed with missing data`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get the webhook for a repo
     * @returns any Returns the webhook data
     * @throws ApiError
     */
    public static getRepoWebhook({
        id,
    }: {
        /**
         * Repo UUID
         */
        id: string,
    }): CancelablePromise<(null | RepoWebhookData)> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos/{id}/webhook',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Database error`,
            },
        });
    }
    /**
     * Register a GitHub webhook for a repo
     * This creates a webhook on GitHub and stores the registration locally
     * @returns RegisterRepoWebhookResponse Webhook registered successfully
     * @throws ApiError
     */
    public static registerRepoWebhook({
        id,
        requestBody,
    }: {
        /**
         * Repo UUID
         */
        id: string,
        requestBody: RegisterRepoWebhookRequest,
    }): CancelablePromise<RegisterRepoWebhookResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/repos/{id}/webhook',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                400: `Failed to create webhook on GitHub`,
                401: `Access token is missing or invalid`,
                404: `Repo not found`,
                409: `Webhook already exists for this repo`,
                500: `Database error`,
            },
        });
    }
    /**
     * Delete a GitHub webhook
     * @returns any Webhook deleted
     * @throws ApiError
     */
    public static deleteRepoWebhook({
        id,
        requestBody,
    }: {
        /**
         * Repo UUID
         */
        id: string,
        requestBody?: DeleteRepoWebhookRequest,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/repos/{id}/webhook',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                404: `Webhook not found`,
                500: `Database error`,
            },
        });
    }
    /**
     * Get webhook events for a repo (audit log)
     * @returns RepoWebhookEvent Returns webhook events
     * @throws ApiError
     */
    public static getWebhookEvents({
        id,
        limit,
        offset,
    }: {
        /**
         * Repo UUID
         */
        id: string,
        /**
         * Number of events to return
         */
        limit?: number,
        /**
         * Number of events to skip
         */
        offset?: number,
    }): CancelablePromise<Array<RepoWebhookEvent>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/repos/{id}/webhook/events',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Webhook not found`,
                500: `Database error`,
            },
        });
    }
    /**
     * Gets a list of all service_definitions
     * @returns PaginatedResponse_ServiceDefinitionData Returns a paginated list of all service_definitions
     * @throws ApiError
     */
    public static getServiceDefinitions({
        limit,
        offset,
    }: {
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<PaginatedResponse_ServiceDefinitionData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-definitions',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get service data via id
     * @returns ServiceDefinitionData Returns service data for given id
     * @throws ApiError
     */
    public static getServiceDefinition({
        id,
    }: {
        id: string,
    }): CancelablePromise<ServiceDefinitionData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-definitions/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Allows a limited set of fields to update on service_definitions by id
     * @returns void
     * @throws ApiError
     */
    public static putServiceDefinition({
        id,
        requestBody,
    }: {
        id: string,
        requestBody: PutServiceData,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/service-definitions/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Removes a build target
     * @returns void
     * @throws ApiError
     */
    public static deleteServiceDefinitions({
        id,
    }: {
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/service-definitions/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Get the manifest path template for a service definition
     * @returns string Returns the manifest path template
     * @throws ApiError
     */
    public static getManifestPathTemplate({
        id,
    }: {
        /**
         * Service Definition UUID
         */
        id: string,
    }): CancelablePromise<string | null> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-definitions/{id}/manifest-path',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service definition not found`,
                500: `Database error`,
            },
        });
    }
    /**
     * Update a service definition's manifest path template
     * @returns PathTemplateValidation Manifest path template updated
     * @throws ApiError
     */
    public static updateManifestPathTemplate({
        id,
        requestBody,
    }: {
        /**
         * Service Definition UUID
         */
        id: string,
        requestBody: UpdateManifestPathTemplate,
    }): CancelablePromise<PathTemplateValidation> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/service-definitions/{id}/manifest-path',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                400: `Invalid path template - missing required placeholders`,
                401: `Access token is missing or invalid`,
                404: `Service definition not found`,
                500: `Database error`,
            },
        });
    }
    /**
     * Gets a list of releases for a given service_definitions via id
     * @returns ReleaseStatus Returns a list of releases for a given service_definitions via id
     * @throws ApiError
     */
    public static getServiceReleases({
        id,
        limit,
        offset,
    }: {
        id: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ReleaseStatus>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-definitions/{id}/releases',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get service versions for a specific service definition
     * @returns ServiceVersionWithDetails Returns a list of versions for the service definition
     * @throws ApiError
     */
    public static getServiceDefinitionVersions({
        serviceDefinitionId,
        includeDeprecated,
        limit,
        offset,
    }: {
        /**
         * Service Definition UUID
         */
        serviceDefinitionId: string,
        /**
         * Include deprecated versions (default: false)
         */
        includeDeprecated?: boolean,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<Array<ServiceVersionWithDetails>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-definitions/{service_definition_id}/versions',
            path: {
                'service_definition_id': serviceDefinitionId,
            },
            query: {
                'include_deprecated': includeDeprecated,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Create a new service version (for CI/CD pipelines)
     * @returns ServiceVersionData Service version already exists with this git_sha (idempotent)
     * @throws ApiError
     */
    public static postServiceVersion({
        requestBody,
    }: {
        requestBody: CreateServiceVersion,
    }): CancelablePromise<ServiceVersionData> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/service-versions',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                400: `Invalid request body`,
                401: `Access token is missing or invalid`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get a single service version by ID
     * @returns ServiceVersionWithDetails Returns the service version
     * @throws ApiError
     */
    public static getServiceVersion({
        id,
    }: {
        /**
         * Service Version UUID
         */
        id: string,
    }): CancelablePromise<ServiceVersionWithDetails> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service-versions/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Delete a service version
     * @returns void
     * @throws ApiError
     */
    public static deleteServiceVersion({
        id,
    }: {
        /**
         * Service Version UUID
         */
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/service-versions/{id}',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Deprecate a service version
     * @returns ServiceVersionData Service version deprecated successfully
     * @throws ApiError
     */
    public static postDeprecateServiceVersion({
        id,
        requestBody,
    }: {
        /**
         * Service Version UUID
         */
        id: string,
        requestBody: DeprecateServiceVersion,
    }): CancelablePromise<ServiceVersionData> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/service-versions/{id}/deprecate',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Pin a service version to protect it from automatic deprecation
     * Pinned versions will not be deprecated when new versions arrive via webhook
     * @returns any Service version pinned successfully
     * @throws ApiError
     */
    public static postPinServiceVersion({
        id,
        requestBody,
    }: {
        /**
         * Service Version UUID
         */
        id: string,
        /**
         * Optional pin details
         */
        requestBody?: (null | PinServiceVersion),
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/service-versions/{id}/pin',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Selects a specific service version for a release
     * This updates the release to use the specified service_version_id
     * @returns void
     * @throws ApiError
     */
    public static putSelectServiceVersion({
        id,
    }: {
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/service-versions/{id}/select',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Unpin a service version, allowing it to be automatically deprecated
     * @returns any Service version unpinned successfully
     * @throws ApiError
     */
    public static postUnpinServiceVersion({
        id,
    }: {
        /**
         * Service Version UUID
         */
        id: string,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/service-versions/{id}/unpin',
            path: {
                'id': id,
            },
            errors: {
                401: `Access token is missing or invalid`,
                404: `Service version not found`,
                500: `Fails on db connection issues`,
            },
        });
    }
    /**
     * Get default service data by name
     * @returns ServiceDefinitionData Returns service data for given name
     * @throws ApiError
     */
    public static getService({
        name,
        limit,
        offset,
    }: {
        name: string,
        /**
         * Number of items to return (default: 50, max: 500)
         */
        limit?: number,
        /**
         * Number of items to skip (default: 0)
         */
        offset?: number,
    }): CancelablePromise<ServiceDefinitionData> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/service/{name}',
            path: {
                'name': name,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Removes a service by name
     * @returns void
     * @throws ApiError
     */
    public static deleteService({
        name,
    }: {
        name: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/service/{name}',
            path: {
                'name': name,
            },
            errors: {
                401: `Access token is missing or invalid`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Adds a new agent user
     * @returns UserData Returns user data on success
     * @throws ApiError
     */
    public static postUser({
        requestBody,
    }: {
        requestBody: PostUser,
    }): CancelablePromise<Array<UserData>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/users',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
                409: `Fails on duplicate entry`,
                422: `Fails when post data is invalid or incomplete`,
                424: `Fails when secret or manifest could not be generated`,
                500: `Fails on db issues`,
            },
        });
    }
    /**
     * Validate a path template without saving it
     * @returns PathTemplateValidation Path template validation result
     * @throws ApiError
     */
    public static validatePathTemplateEndpoint({
        requestBody,
    }: {
        requestBody: UpdateManifestPathTemplate,
    }): CancelablePromise<PathTemplateValidation> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/validate-path-template',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Access token is missing or invalid`,
            },
        });
    }
    /**
     * Get beecd-hive-hq version
     * @returns string Returns version of hq
     * @throws ApiError
     */
    public static version(): CancelablePromise<string> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/version',
        });
    }
}
