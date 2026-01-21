import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '@/lib/api-client';
import type {
    PaginatedResponse,
    PaginationParams,
    Cluster,
    ClusterNamespaceServicesData,
    Heartbeat,
    HiveError,
    RepoData,
    RepoBranch,
    ServiceDefinitionData,
    ClusterGroupData,
    ClusterGroupServices,
    ClusterGroupClusterAssociation,
    ClusterClusterGroups,
    ClusterServiceDefinitions,
    AdditionalInstallation,
    ReleaseStatus,
    ServiceVersionForRelease,
    DiffDataWithBody,
    RepoWebhookData,
    RegisterRepoWebhookRequest,
    RegisterRepoWebhookResponse,
    RepoWebhookEvent,
    PathTemplateValidation,
    UpdateManifestPathTemplate,
} from '@/types';

// Query keys factory
export const queryKeys = {
    clusters: {
        all: ['clusters'] as const,
        list: (params: PaginationParams) => [...queryKeys.clusters.all, 'list', params] as const,
        detail: (id: string) => [...queryKeys.clusters.all, 'detail', id] as const,
    },
    repos: {
        all: ['repos'] as const,
        list: (params: PaginationParams) => [...queryKeys.repos.all, 'list', params] as const,
        detail: (id: string) => [...queryKeys.repos.all, 'detail', id] as const,
    },
    services: {
        all: ['services'] as const,
        list: (params: PaginationParams) => [...queryKeys.services.all, 'list', params] as const,
        detail: (id: string) => [...queryKeys.services.all, 'detail', id] as const,
        byName: (name: string) => [...queryKeys.services.all, 'byName', name] as const,
    },
    clusterGroups: {
        all: ['clusterGroups'] as const,
        list: (params: PaginationParams) => [...queryKeys.clusterGroups.all, 'list', params] as const,
        detail: (id: string) => [...queryKeys.clusterGroups.all, 'detail', id] as const,
    },
    releases: {
        all: ['releases'] as const,
        detail: (namespaceId: string, releaseName: string) => [...queryKeys.releases.all, 'detail', namespaceId, releaseName] as const,
        diff: (releaseId: string, diffGeneration: number) => [...queryKeys.releases.all, 'diff', releaseId, diffGeneration] as const,
    },
};

// Clusters API
export function useClusters(params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: queryKeys.clusters.list(params),
        queryFn: async () => {
            const response = await apiClient.get<PaginatedResponse<Cluster>>('/clusters', {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
    });
}

export function useCluster(id: string) {
    return useQuery({
        queryKey: queryKeys.clusters.detail(id),
        queryFn: async () => {
            const response = await apiClient.get<Cluster>(`/clusters/${id}`);
            return response.data;
        },
        enabled: !!id,
    });
}

export function useDeleteCluster() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (id: string) => {
            await apiClient.delete(`/clusters/${id}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Response type for cluster creation
interface PostClusterResponse {
    cluster: Cluster;
    manifest: string | null;
    manifest_is_placeholder: boolean;
    user_existed: boolean;
    secret_regenerated: boolean;
}

// Create a new cluster with optional manifest generation
export function useCreateCluster() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({
            name,
            context,
            regenerateSecret
        }: {
            name: string;
            context?: {
                agent_name?: string;
                namespace?: string;
                grpc_address?: string;
                grpc_tls?: boolean;
                image?: string;
            };
            regenerateSecret?: boolean;
        }) => {
            const response = await apiClient.post<PostClusterResponse>('/clusters', {
                name,
                context: context || {},
                regenerate_secret: regenerateSecret
            });
            return response.data;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Repos API
export function useRepos(params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: queryKeys.repos.list(params),
        queryFn: async () => {
            const response = await apiClient.get<PaginatedResponse<RepoData>>('/repos', {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
    });
}

export function useRepo(id: string) {
    return useQuery({
        queryKey: queryKeys.repos.detail(id),
        queryFn: async () => {
            const response = await apiClient.get<RepoData>(`/repos/${id}`);
            return response.data;
        },
        enabled: !!id,
    });
}

// Create a new repo
export function useCreateRepo() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ url, provider }: { url: string; provider?: string }) => {
            const response = await apiClient.post<RepoData>('/repos', {
                url,
                ...(provider ? { provider } : {}),
            });
            return response.data;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.repos.all });
        },
    });
}

// Add a branch to a repo
export function useAddRepoBranch() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ repoId, branch }: { repoId: string; branch: string }) => {
            await apiClient.post(`/repos/${repoId}/branches`, { branch });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.repos.all });
        },
    });
}

// Add a service to a repo (applies to all branches)
export function useAddRepoService() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ repoId, name, manifestPathTemplate }: { repoId: string; name: string; manifestPathTemplate?: string }) => {
            await apiClient.post(`/repos/${repoId}/service-definitions`, {
                name,
                manifest_path_template: manifestPathTemplate || null,
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.repos.all });
            queryClient.invalidateQueries({ queryKey: queryKeys.services.all });
        },
    });
}

// Service Definitions API
export function useServiceDefinitions(params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: queryKeys.services.list(params),
        queryFn: async () => {
            const response = await apiClient.get<PaginatedResponse<ServiceDefinitionData>>('/service-definitions', {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
    });
}

export function useServiceDefinition(id: string) {
    return useQuery({
        queryKey: queryKeys.services.detail(id),
        queryFn: async () => {
            const response = await apiClient.get<ServiceDefinitionData>(`/service-definitions/${id}`);
            return response.data;
        },
        enabled: !!id,
    });
}

export function useServiceByName(name: string) {
    return useQuery({
        queryKey: queryKeys.services.byName(name),
        queryFn: async () => {
            const response = await apiClient.get<ServiceDefinitionData[]>(`/service/${name}`);
            return response.data;
        },
        enabled: !!name,
    });
}

export function useDeleteService() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (serviceName: string) => {
            await apiClient.delete(`/service/${serviceName}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.services.all });
        },
    });
}

// Cluster Groups API
export function useClusterGroups(params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: queryKeys.clusterGroups.list(params),
        queryFn: async () => {
            const response = await apiClient.get<PaginatedResponse<ClusterGroupData>>('/cluster-groups', {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
    });
}

export function useClusterGroup(id: string) {
    return useQuery({
        queryKey: queryKeys.clusterGroups.detail(id),
        queryFn: async () => {
            const response = await apiClient.get<ClusterGroupData>(`/cluster-groups/${id}`);
            return response.data;
        },
        enabled: !!id,
    });
}

// Cluster Detail APIs
export function useClusterNamespaces(clusterId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'namespaces', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ClusterNamespaceServicesData[]>(`/clusters/${clusterId}/namespaces`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!clusterId,
    });
}

export function useClusterReleases(clusterId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'releases', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ReleaseStatus[]>(`/clusters/${clusterId}/releases`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!clusterId,
    });
}

export function useClusterErrors(clusterId: string) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'errors'] as const,
        queryFn: async () => {
            const response = await apiClient.get<HiveError[]>(`/clusters/${clusterId}/errors`);
            return response.data;
        },
        enabled: !!clusterId,
    });
}

export function useClusterHeartbeat(clusterId: string) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'heartbeat'] as const,
        queryFn: async () => {
            const response = await apiClient.get<Heartbeat>(`/clusters/${clusterId}/heartbeat`);
            return response.data;
        },
        enabled: !!clusterId,
    });
}

export function useClusterGroups_ForCluster(clusterId: string) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'groups'] as const,
        queryFn: async () => {
            const response = await apiClient.get<ClusterClusterGroups[]>(`/clusters/${clusterId}/groups`);
            return response.data;
        },
        enabled: !!clusterId,
    });
}

export function useClusterServiceDefinitions(clusterId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.clusters.detail(clusterId), 'service-definitions', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ClusterServiceDefinitions[]>(`/clusters/${clusterId}/service-definitions`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!clusterId,
    });
}

// Repo Detail APIs
export function useRepoBranches(repoId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.repos.detail(repoId), 'branches', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<RepoBranch[]>(`/repos/${repoId}/branches`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!repoId,
    });
}

export function useRepoServiceDefinitions(repoId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.repos.detail(repoId), 'service-definitions', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ServiceDefinitionData[]>(`/repos/${repoId}/service-definitions`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!repoId,
    });
}

// Cluster Group Detail APIs
export function useClusterGroupServices(groupId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.clusterGroups.detail(groupId), 'services', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ClusterGroupServices[]>(`/cluster-groups/${groupId}/service-definitions`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!groupId,
    });
}

export function useClusterGroupClusters(groupId: string) {
    return useQuery({
        queryKey: [...queryKeys.clusterGroups.detail(groupId), 'clusters'] as const,
        queryFn: async () => {
            const response = await apiClient.get<ClusterGroupClusterAssociation[]>(`/cluster-groups/${groupId}/clusters`);
            return response.data;
        },
        enabled: !!groupId,
    });
}

// Get unassociated service definitions for a cluster group with pagination
export function useUnassociatedServiceDefinitions(groupId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...queryKeys.clusterGroups.detail(groupId), 'unassociated-services', params] as const,
        queryFn: async () => {
            const response = await apiClient.get<ServiceDefinitionData[]>(`/cluster-groups/${groupId}/unassociated-service-definitions`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!groupId,
    });
}

// Mutations

// Add namespaces to cluster
export function useAddClusterNamespaces() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ clusterId, namespaceNames }: { clusterId: string; namespaceNames: string[] }) => {
            await apiClient.post(`/clusters/${clusterId}/namespaces`, { namespace_names: namespaceNames });
        },
        onSuccess: (_, { clusterId }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.detail(clusterId) });
        },
    });
}

// Add services to namespace (init release)
export function useInitNamespaceServices() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ namespaceId, serviceDefinitionIds }: { namespaceId: string; serviceDefinitionIds: string[] }) => {
            const response = await apiClient.post<AdditionalInstallation[]>(
                `/releases/namespaces/${namespaceId}/init`,
                { service_definition_ids: serviceDefinitionIds }
            );
            return response.data;
        },
        onSuccess: () => {
            // Invalidate cluster queries to refresh namespaces and releases
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Remove service from namespace
export function useRemoveServiceFromNamespace() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ namespaceId, serviceName }: { namespaceId: string; serviceName: string }) => {
            await apiClient.delete(`/namespaces/${namespaceId}/service-name/${serviceName}`);
        },
        onSuccess: () => {
            // Invalidate cluster queries to refresh namespaces and releases
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Create new user (generate manifest)
interface UserData {
    secret: string;
    manifest: string;
}

interface PostUserContext {
    agent_name?: string;
    namespace?: string;
    grpc_address?: string;
    image?: string;
}

export function useCreateUser() {
    return useMutation({
        mutationFn: async ({ name, context }: { name: string; context?: PostUserContext }) => {
            const response = await apiClient.post<UserData>('/users', { name, context });
            return response.data;
        },
    });
}

// Approve releases
export function useApproveReleases() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (releaseIds: string[]) => {
            const response = await apiClient.put('/approvals', { ids: releaseIds });
            return response.data;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Unapprove releases
export function useUnapproveReleases() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (releaseIds: string[]) => {
            await apiClient.put('/approvals/unapprove', { ids: releaseIds });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Subscribe clusters to group
export function useSubscribeClustersToGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ groupId, clusterIds }: { groupId: string; clusterIds: string[] }) => {
            await apiClient.post(`/cluster-groups/${groupId}/clusters`, { ids: clusterIds });
        },
        onSuccess: (_, { groupId }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.detail(groupId) });
        },
    });
}

// Unsubscribe cluster from group
export function useUnsubscribeClusterFromGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ clusterId, groupId }: { clusterId: string; groupId: string }) => {
            await apiClient.delete(`/clusters/${clusterId}/groups/${groupId}`);
        },
        onSuccess: (_, { groupId }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.detail(groupId) });
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Delete cluster group
export function useDeleteClusterGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (id: string) => {
            await apiClient.delete(`/cluster-groups/${id}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.all });
        },
    });
}

// Create cluster group
export function useCreateClusterGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ name, priority }: { name: string; priority?: number }) => {
            const response = await apiClient.post('/cluster-groups', { name, priority });
            return response.data;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.all });
        },
    });
}

// Update cluster group
export function useUpdateClusterGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ id, name, priority }: { id: string; name?: string; priority?: number }) => {
            await apiClient.put(`/cluster-groups/${id}`, { name, priority });
        },
        onSuccess: (_, { id }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.detail(id) });
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.all });
        },
    });
}

// Subscribe service definitions to cluster group
export function useSubscribeServiceDefinitionsToGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ groupId, serviceDefinitionIds }: { groupId: string; serviceDefinitionIds: string[] }) => {
            await apiClient.post(`/cluster-groups/${groupId}/service-definitions`, { ids: serviceDefinitionIds });
        },
        onSuccess: (_, { groupId }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.detail(groupId) });
        },
    });
}

// Unsubscribe service definition from cluster group
export function useUnsubscribeServiceDefinitionFromGroup() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ groupId, serviceDefinitionId }: { groupId: string; serviceDefinitionId: string }) => {
            await apiClient.delete(`/cluster-groups/${groupId}/service-definitions/${serviceDefinitionId}`);
        },
        onSuccess: (_, { groupId }) => {
            queryClient.invalidateQueries({ queryKey: queryKeys.clusterGroups.detail(groupId) });
        },
    });
}

// Get release by namespace id and name (current/active version)
export function useRelease(namespaceId: string, releaseName: string) {
    return useQuery({
        queryKey: queryKeys.releases.detail(namespaceId, releaseName),
        queryFn: async () => {
            // Use the /current endpoint which returns a single ReleaseStatus
            const response = await apiClient.get<ReleaseStatus>(`/namespaces/${namespaceId}/release/${releaseName}/current`);
            return response.data;
        },
        enabled: !!namespaceId && !!releaseName,
    });
}

// Get all available service versions for a release (for version selection UI)
// Returns paginated results
export function useReleaseVersions(
    namespaceId: string,
    releaseName: string,
    options?: { deployedOnly?: boolean; limit?: number; offset?: number }
) {
    return useQuery({
        queryKey: [...queryKeys.releases.detail(namespaceId, releaseName), 'versions', options] as const,
        queryFn: async () => {
            const params = new URLSearchParams();
            if (options?.deployedOnly) params.set('deployed_only', 'true');
            if (options?.limit) params.set('limit', options.limit.toString());
            if (options?.offset) params.set('offset', options.offset.toString());
            const queryStr = params.toString();
            const url = `/namespaces/${namespaceId}/release/${releaseName}/versions${queryStr ? `?${queryStr}` : ''}`;
            const response = await apiClient.get<PaginatedResponse<ServiceVersionForRelease>>(url);
            return response.data;
        },
        enabled: !!namespaceId && !!releaseName,
    });
}

// Select a specific service version for a release (creates new release with this version)
export function useSelectServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (serviceVersionId: string) => {
            await apiClient.put(`/service-versions/${serviceVersionId}/select`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.releases.all });
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
        },
    });
}

// Legacy: Select a specific release version (deprecated - use useSelectServiceVersion instead)
export function useSelectReleaseVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (releaseId: string) => {
            await apiClient.put(`/releases/${releaseId}/select`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.releases.all });
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Restore to latest release (remove manual selection)
export function useRestoreLatestRelease() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ namespaceId, releaseName }: { namespaceId: string; releaseName: string }) => {
            await apiClient.put(`/namespaces/${namespaceId}/release/${releaseName}/latest`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.releases.all });
            queryClient.invalidateQueries({ queryKey: queryKeys.clusters.all });
        },
    });
}

// Pin a service version (prevents auto-deprecation from webhooks)
export function usePinServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (serviceVersionId: string) => {
            await apiClient.post(`/service-versions/${serviceVersionId}/pin`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.releases.all });
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
        },
    });
}

// Unpin a service version (allows auto-deprecation from webhooks)
export function useUnpinServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (serviceVersionId: string) => {
            await apiClient.post(`/service-versions/${serviceVersionId}/unpin`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: queryKeys.releases.all });
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
        },
    });
}

// Get release diffs
export function useReleaseDiff(releaseId: string, diffGeneration: number, enabled = true) {
    // Use -1 (latest) when diff_generation is 0 to fetch whatever diffs exist
    const effectiveDiffGen = diffGeneration === 0 ? -1 : diffGeneration;
    return useQuery({
        queryKey: queryKeys.releases.diff(releaseId, effectiveDiffGen),
        queryFn: async () => {
            const response = await apiClient.get<DiffDataWithBody[]>(`/releases/${releaseId}/diff/${effectiveDiffGen}`);
            return response.data;
        },
        // Query is enabled when we have a releaseId; diff_generation 0 means no diffs yet (will show empty)
        enabled: enabled && !!releaseId,
    });
}

// Service Versions API
import type { ServiceVersionWithDetails, CreateServiceVersion } from '@/types';

export const serviceVersionKeys = {
    all: ['serviceVersions'] as const,
    byServiceDefinition: (serviceDefId: string) => [...serviceVersionKeys.all, 'byServiceDef', serviceDefId] as const,
    byNamespace: (namespaceId: string) => [...serviceVersionKeys.all, 'byNamespace', namespaceId] as const,
    detail: (id: string) => [...serviceVersionKeys.all, 'detail', id] as const,
};

// Get all versions for a service definition
export function useServiceDefinitionVersions(serviceDefinitionId: string) {
    return useQuery({
        queryKey: serviceVersionKeys.byServiceDefinition(serviceDefinitionId),
        queryFn: async () => {
            const response = await apiClient.get<ServiceVersionWithDetails[]>(`/service-definitions/${serviceDefinitionId}/versions`);
            return response.data;
        },
        enabled: !!serviceDefinitionId,
    });
}

// Get all versions for a namespace
export function useNamespaceServiceVersions(namespaceId: string) {
    return useQuery({
        queryKey: serviceVersionKeys.byNamespace(namespaceId),
        queryFn: async () => {
            const response = await apiClient.get<ServiceVersionWithDetails[]>(`/namespaces/${namespaceId}/service-versions`);
            return response.data;
        },
        enabled: !!namespaceId,
    });
}

// Get a single service version
export function useServiceVersion(id: string) {
    return useQuery({
        queryKey: serviceVersionKeys.detail(id),
        queryFn: async () => {
            const response = await apiClient.get<ServiceVersionWithDetails>(`/service-versions/${id}`);
            return response.data;
        },
        enabled: !!id,
    });
}

// Create a new service version
export function useCreateServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (data: CreateServiceVersion) => {
            const response = await apiClient.post<ServiceVersionWithDetails>('/service-versions', data);
            return response.data;
        },
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.byServiceDefinition(variables.service_definition_id) });
            if (variables.namespace_id) {
                queryClient.invalidateQueries({ queryKey: serviceVersionKeys.byNamespace(variables.namespace_id) });
            }
        },
    });
}

// Deprecate a service version
export function useDeprecateServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ id, reason }: { id: string; reason?: string }) => {
            await apiClient.post(`/service-versions/${id}/deprecate`, { reason });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
        },
    });
}

// Delete a service version
export function useDeleteServiceVersion() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (id: string) => {
            await apiClient.delete(`/service-versions/${id}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: serviceVersionKeys.all });
        },
    });
}

// ==========================================
// GitHub Webhooks API
// ==========================================

export const webhookKeys = {
    all: ['webhooks'] as const,
    repo: (repoId: string) => [...webhookKeys.all, 'repo', repoId] as const,
    events: (repoId: string) => [...webhookKeys.all, 'events', repoId] as const,
};

// Get webhook for a repo
export function useRepoWebhook(repoId: string) {
    return useQuery({
        queryKey: webhookKeys.repo(repoId),
        queryFn: async () => {
            const response = await apiClient.get<RepoWebhookData>(`/repos/${repoId}/webhook`);
            return response.data;
        },
        enabled: !!repoId,
        retry: false, // Don't retry 404s
    });
}

// Register a webhook for a repo
export function useRegisterWebhook() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ repoId, githubToken }: { repoId: string; githubToken: string }) => {
            const response = await apiClient.post<RegisterRepoWebhookResponse>(
                `/repos/${repoId}/webhook`,
                { github_token: githubToken } as RegisterRepoWebhookRequest
            );
            return response.data;
        },
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: webhookKeys.repo(variables.repoId) });
        },
    });
}

// Delete a webhook for a repo
export function useDeleteWebhook() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ repoId, githubToken }: { repoId: string; githubToken?: string }) => {
            const token = githubToken?.trim();
            if (token) {
                await apiClient.delete(`/repos/${repoId}/webhook`, {
                    data: { github_token: token },
                });
            } else {
                await apiClient.delete(`/repos/${repoId}/webhook`);
            }
        },
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: webhookKeys.repo(variables.repoId) });
        },
    });
}

// Get webhook events for a repo
export function useWebhookEvents(repoId: string, params: PaginationParams = { limit: 50, offset: 0 }) {
    return useQuery({
        queryKey: [...webhookKeys.events(repoId), params] as const,
        queryFn: async () => {
            const response = await apiClient.get<RepoWebhookEvent[]>(`/repos/${repoId}/webhook/events`, {
                params: { limit: params.limit, offset: params.offset },
            });
            return response.data;
        },
        enabled: !!repoId,
    });
}

// ==========================================
// Manifest Path Template API
// ==========================================

export const pathTemplateKeys = {
    all: ['pathTemplates'] as const,
    service: (serviceDefinitionId: string) => [...pathTemplateKeys.all, 'service', serviceDefinitionId] as const,
};

// Get manifest path template for a service definition
export function useManifestPathTemplate(serviceDefinitionId: string) {
    return useQuery({
        queryKey: pathTemplateKeys.service(serviceDefinitionId),
        queryFn: async () => {
            const response = await apiClient.get<{ manifest_path_template: string | null }>(
                `/service-definitions/${serviceDefinitionId}/manifest-path`
            );
            return response.data;
        },
        enabled: !!serviceDefinitionId,
    });
}

// Update manifest path template for a service definition
export function useUpdateManifestPathTemplate() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ serviceDefinitionId, manifestPathTemplate }: { serviceDefinitionId: string; manifestPathTemplate: string }) => {
            const response = await apiClient.put<{ manifest_path_template: string }>(
                `/service-definitions/${serviceDefinitionId}/manifest-path`,
                { manifest_path_template: manifestPathTemplate } as UpdateManifestPathTemplate
            );
            return response.data;
        },
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: pathTemplateKeys.service(variables.serviceDefinitionId) });
            queryClient.invalidateQueries({ queryKey: queryKeys.services.detail(variables.serviceDefinitionId) });
        },
    });
}

// Validate a path template
export function useValidatePathTemplate() {
    return useMutation({
        mutationFn: async (template: string) => {
            const response = await apiClient.post<PathTemplateValidation>(
                '/validate-path-template',
                { manifest_path_template: template }
            );
            return response.data;
        },
    });
}
