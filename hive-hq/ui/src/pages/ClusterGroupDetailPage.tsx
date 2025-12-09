import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Server, Package, Trash2, Edit, Plus, X } from 'lucide-react';
import { PageHeader, DataTable, Alert, Modal, ConfirmModal } from '@/components';
import apiClient from '@/lib/api-client';
import {
    useClusterGroup,
    useDeleteClusterGroup,
    useUpdateClusterGroup,
    useSubscribeClustersToGroup,
    useUnsubscribeClusterFromGroup,
    useSubscribeServiceDefinitionsToGroup,
    useUnsubscribeServiceDefinitionFromGroup,
    usePaginatedData,
} from '@/hooks';
import type { ClusterGroupServices, ClusterGroupClusterAssociation, ServiceDefinitionData } from '@/types';

function getUserFriendlyApiError(err: unknown, fallbackMessage: string): string {
    if (err && typeof err === 'object' && 'response' in err) {
        const maybeAxiosError = err as { response?: { data?: unknown } };
        const data = maybeAxiosError.response?.data;

        if (typeof data === 'string' && data.trim()) {
            return data;
        }

        if (data && typeof data === 'object' && 'message' in data) {
            const message = (data as { message?: unknown }).message;
            if (typeof message === 'string' && message.trim()) {
                return message;
            }
        }
    }

    if (err instanceof Error && err.message.trim()) {
        return err.message;
    }

    return fallbackMessage;
}

async function resolveServiceIdsInErrorMessage(
    message: string,
    servicesInGroup: ClusterGroupServices[],
): Promise<string> {
    const matches = Array.from(message.matchAll(/\bServiceId\s+([0-9a-fA-F-]{36})\b/g));
    if (matches.length === 0) return message;

    const uniqueIds = Array.from(new Set(matches.map((m) => m[1])));
    const resolvedDisplay = new Map<string, string>();

    for (const id of uniqueIds) {
        const fromGroup = servicesInGroup.find((s) => s.service_definition_id === id);
        if (fromGroup?.service_name) {
            const repoDisplay = fromGroup.org && fromGroup.repo ? ` (${fromGroup.org}/${fromGroup.repo})` : '';
            resolvedDisplay.set(id, `${fromGroup.service_name}${repoDisplay}`);
            continue;
        }

        try {
            const response = await apiClient.get<ServiceDefinitionData>(`/service-definitions/${id}`);
            if (response.data?.name) {
                const repoDisplay = response.data.org && response.data.repo ? ` (${response.data.org}/${response.data.repo})` : '';
                resolvedDisplay.set(id, `${response.data.name}${repoDisplay}`);
            }
        } catch {
            // Best-effort only; keep original ID if lookup fails.
        }
    }

    return message.replace(/\bServiceId\s+([0-9a-fA-F-]{36})\b/g, (_full, id: string) => {
        const display = resolvedDisplay.get(id);
        if (!display) return `ServiceId ${id}`;
        return `Service \"${display}\" (ServiceId ${id})`;
    });
}

// Edit Group Modal Component
function EditGroupModal({
    isOpen,
    onClose,
    onSubmit,
    isPending,
    initialName,
    initialPriority,
}: {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (data: { name: string; priority: number }) => void;
    isPending: boolean;
    initialName: string;
    initialPriority: number;
}) {
    const [name, setName] = useState(initialName);
    const [priority, setPriority] = useState(initialPriority);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        onSubmit({ name, priority });
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Edit Cluster Group" size="md">
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    <div>
                        <label htmlFor="name" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Group Name
                        </label>
                        <input
                            type="text"
                            id="name"
                            className="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div>
                        <label htmlFor="priority" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Priority
                        </label>
                        <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">
                            Lower numbers have higher priority
                        </p>
                        <input
                            type="number"
                            id="priority"
                            min={0}
                            className="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                            value={priority}
                            onChange={(e) => setPriority(parseInt(e.target.value, 10) || 0)}
                        />
                    </div>
                </div>
                <div className="mt-6 flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={isPending || !name.trim()}
                        className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isPending ? 'Saving...' : 'Save Changes'}
                    </button>
                </div>
            </form>
        </Modal>
    );
}

// Add Clusters Modal Component
function AddClustersModal({
    isOpen,
    onClose,
    onSubmit,
    isPending,
    groupId,
    submitError,
    onDismissSubmitError,
}: {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (clusterIds: string[], clusterNames: string[]) => void;
    isPending: boolean;
    groupId: string;
    submitError?: string | null;
    onDismissSubmitError?: () => void;
}) {
    const [selectedClusters, setSelectedClusters] = useState<Set<string>>(new Set());
    const [searchTerm, setSearchTerm] = useState('');
    const [allClusters, setAllClusters] = useState<ClusterGroupClusterAssociation[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [loadError, setLoadError] = useState<string | null>(null);

    // Load clusters when modal opens
    useEffect(() => {
        if (isOpen) {
            setSelectedClusters(new Set());
            setSearchTerm('');
            setAllClusters([]);
            setIsLoading(true);
            setLoadError(null);

            // Load all unassociated clusters
            apiClient
                .get<ClusterGroupClusterAssociation[]>(`/cluster-groups/${groupId}/clusters`)
                .then((response) => {
                    const unassociated = response.data.filter(c => !c.associated);
                    setAllClusters(unassociated);
                })
                .catch((error) => {
                    console.error('Error loading clusters:', error);
                    setLoadError(getUserFriendlyApiError(error, 'Failed to load available clusters. Please try again.'));
                })
                .finally(() => {
                    setIsLoading(false);
                });
        }
    }, [isOpen, groupId]);

    // Filter clusters based on search term
    const filteredClusters = allClusters.filter(cluster => {
        if (!searchTerm) return true;
        const search = searchTerm.toLowerCase();
        return cluster.name.toLowerCase().includes(search);
    });

    const toggleCluster = (clusterId: string) => {
        setSelectedClusters(prev => {
            const newSet = new Set(prev);
            if (newSet.has(clusterId)) {
                newSet.delete(clusterId);
            } else {
                newSet.add(clusterId);
            }
            return newSet;
        });
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (selectedClusters.size > 0) {
            const selectedIds = Array.from(selectedClusters);
            const selectedNames = selectedIds
                .map((id) => allClusters.find((c) => c.id === id)?.name)
                .filter((name): name is string => !!name);
            onSubmit(selectedIds, selectedNames);
            setSelectedClusters(new Set());
        }
    };

    const handleClose = () => {
        setSelectedClusters(new Set());
        setSearchTerm('');
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Add Clusters to Group" size="md">
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    {submitError && (
                        <Alert
                            type="error"
                            title="Couldn't add clusters"
                            message={submitError}
                            onDismiss={onDismissSubmitError}
                        />
                    )}

                    {loadError && (
                        <Alert
                            type="error"
                            title="Couldn't load clusters"
                            message={loadError}
                            onDismiss={() => setLoadError(null)}
                        />
                    )}

                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Select clusters to add to this group
                    </p>

                    {/* Search input */}
                    <div>
                        <input
                            type="text"
                            placeholder="Search clusters by name..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                        />
                    </div>

                    <div className="max-h-64 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-md">
                        {isLoading ? (
                            <div className="flex items-center justify-center p-8">
                                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                                <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">Loading clusters...</span>
                            </div>
                        ) : filteredClusters.length === 0 ? (
                            <p className="p-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                                {searchTerm ? 'No clusters match your search' : 'No available clusters to add'}
                            </p>
                        ) : (
                            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                                {filteredClusters.map((cluster) => (
                                    <li key={cluster.id} className="p-3 hover:bg-gray-50 dark:hover:bg-gray-800">
                                        <label className="flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={selectedClusters.has(cluster.id)}
                                                onChange={() => toggleCluster(cluster.id)}
                                                className="h-4 w-4 text-blue-600 rounded border-gray-300 dark:border-gray-600 dark:bg-gray-800 focus:ring-blue-500"
                                            />
                                            <span className="ml-3 text-sm font-medium text-gray-900 dark:text-gray-100">
                                                {cluster.name}
                                            </span>
                                        </label>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>

                    {/* Selection count */}
                    {selectedClusters.size > 0 && (
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            {selectedClusters.size} cluster{selectedClusters.size !== 1 ? 's' : ''} selected
                        </p>
                    )}
                </div>
                <div className="mt-6 flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={handleClose}
                        className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={isPending || selectedClusters.size === 0}
                        className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isPending ? 'Adding...' : `Add ${selectedClusters.size} Cluster${selectedClusters.size !== 1 ? 's' : ''}`}
                    </button>
                </div>
            </form>
        </Modal>
    );
}

// Add Services Modal Component with pagination and search
function AddServicesModal({
    isOpen,
    onClose,
    onSubmit,
    isPending,
    groupId,
    submitError,
    onDismissSubmitError,
}: {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (serviceDefinitionIds: string[], serviceNames: string[]) => void;
    isPending: boolean;
    groupId: string;
    submitError?: string | null;
    onDismissSubmitError?: () => void;
}) {
    const [selectedServices, setSelectedServices] = useState<Set<string>>(new Set());
    const [searchTerm, setSearchTerm] = useState('');
    const [allServices, setAllServices] = useState<ServiceDefinitionData[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [allDataLoaded, setAllDataLoaded] = useState(false);
    const [loadError, setLoadError] = useState<string | null>(null);
    const PAGE_SIZE = 50;

    // Load all services when modal opens
    const loadAllServices = async () => {
        setIsLoading(true);
        setAllServices([]);
        setAllDataLoaded(false);
        setLoadError(null);

        try {
            let allData: ServiceDefinitionData[] = [];
            let offset = 0;
            let hasMoreData = true;

            // Load first page
            const firstResponse = await apiClient.get<ServiceDefinitionData[]>(
                `/cluster-groups/${groupId}/unassociated-service-definitions`,
                { params: { limit: PAGE_SIZE, offset: 0 } }
            );
            allData = firstResponse.data;
            hasMoreData = firstResponse.data.length === PAGE_SIZE;
            offset = PAGE_SIZE;

            setAllServices(allData);
            setIsLoading(false);

            // Continue loading remaining pages in background
            while (hasMoreData) {
                setIsLoadingMore(true);
                const response = await apiClient.get<ServiceDefinitionData[]>(
                    `/cluster-groups/${groupId}/unassociated-service-definitions`,
                    { params: { limit: PAGE_SIZE, offset } }
                );
                const newServices = response.data;
                allData = [...allData, ...newServices];
                setAllServices(allData);
                hasMoreData = newServices.length === PAGE_SIZE;
                offset += PAGE_SIZE;
            }

            setAllDataLoaded(true);
        } catch (err) {
            console.error('Failed to load services:', err);
            setLoadError(getUserFriendlyApiError(err, 'Failed to load available services. Please try again.'));
        } finally {
            setIsLoading(false);
            setIsLoadingMore(false);
        }
    };

    // Reset state when modal opens
    useEffect(() => {
        if (isOpen) {
            setSearchTerm('');
            setSelectedServices(new Set());
            loadAllServices();
        }
    }, [isOpen, groupId]);

    // Filter services by search term
    const filteredServices = allServices.filter(service => {
        if (!searchTerm) return true;
        const search = searchTerm.toLowerCase();
        return (
            service.name.toLowerCase().includes(search) ||
            service.org.toLowerCase().includes(search) ||
            service.repo.toLowerCase().includes(search) ||
            service.branch.toLowerCase().includes(search)
        );
    });

    const toggleService = (serviceId: string) => {
        setSelectedServices(prev => {
            const newSet = new Set(prev);
            if (newSet.has(serviceId)) {
                newSet.delete(serviceId);
            } else {
                newSet.add(serviceId);
            }
            return newSet;
        });
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (selectedServices.size > 0) {
            const selectedIds = Array.from(selectedServices);
            const selectedNames = selectedIds
                .map((id) => allServices.find((s) => s.service_definition_id === id))
                .filter((s): s is ServiceDefinitionData => !!s)
                .map((s) => `${s.name} (${s.org}/${s.repo})`);

            onSubmit(selectedIds, selectedNames);
            setSelectedServices(new Set());
        }
    };

    const handleClose = () => {
        setSelectedServices(new Set());
        setSearchTerm('');
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Add Service Definitions to Group" size="lg">
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    {submitError && (
                        <Alert
                            type="error"
                            title="Couldn't add services"
                            message={submitError}
                            onDismiss={onDismissSubmitError}
                        />
                    )}

                    {loadError && (
                        <Alert
                            type="error"
                            title="Couldn't load services"
                            message={loadError}
                            onDismiss={() => setLoadError(null)}
                        />
                    )}

                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Select service definitions to deploy to clusters in this group
                    </p>

                    {/* Search input */}
                    <div className="relative">
                        <input
                            type="text"
                            placeholder="Search services by name, repo, or branch..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                        />
                        {isLoadingMore && (
                            <span className="absolute right-3 top-2 text-xs text-gray-400">Loading all...</span>
                        )}
                    </div>

                    <div className="max-h-96 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-md">
                        {isLoading ? (
                            <div className="flex items-center justify-center p-8">
                                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                                <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">Loading services...</span>
                            </div>
                        ) : filteredServices.length === 0 ? (
                            <p className="p-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                                {searchTerm ? 'No services match your search' : 'No available service definitions to add'}
                            </p>
                        ) : (
                            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                                {filteredServices.map((service) => (
                                    <li key={service.service_definition_id} className="p-3 hover:bg-gray-50 dark:hover:bg-gray-800">
                                        <label className="flex items-start cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={selectedServices.has(service.service_definition_id)}
                                                onChange={() => toggleService(service.service_definition_id)}
                                                className="mt-1 h-4 w-4 text-blue-600 rounded border-gray-300 dark:border-gray-600 dark:bg-gray-800 focus:ring-blue-500"
                                            />
                                            <div className="ml-3">
                                                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                                    {service.name}
                                                </span>
                                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                                    {service.org}/{service.repo} • {service.branch}
                                                </p>
                                            </div>
                                        </label>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>

                    {/* Status info */}
                    <div className="flex justify-between text-sm text-gray-500 dark:text-gray-400">
                        <span>{allServices.length} services loaded{!allDataLoaded && isLoadingMore ? ' (loading more...)' : ''}</span>
                        {selectedServices.size > 0 && (
                            <span>{selectedServices.size} selected</span>
                        )}
                    </div>
                </div>
                <div className="mt-6 flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={handleClose}
                        className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={isPending || selectedServices.size === 0}
                        className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isPending ? 'Adding...' : `Add ${selectedServices.size} Service${selectedServices.size !== 1 ? 's' : ''}`}
                    </button>
                </div>
            </form>
        </Modal>
    );
}

export function ClusterGroupDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    // State for modals
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showAddClustersModal, setShowAddClustersModal] = useState(false);
    const [clusterToRemove, setClusterToRemove] = useState<ClusterGroupClusterAssociation | null>(null);
    const [showAddServicesModal, setShowAddServicesModal] = useState(false);
    const [serviceToRemove, setServiceToRemove] = useState<ClusterGroupServices | null>(null);
    const [addClustersError, setAddClustersError] = useState<string | null>(null);
    const [addServicesError, setAddServicesError] = useState<string | null>(null);

    // Queries
    const { data: group, isLoading, isError, error, refetch: refetchGroup } = useClusterGroup(id!);

    // Paginated data - loads all pages for proper search
    const {
        data: services = [],
        isLoading: loadingServices,
        isLoadingMore: loadingMoreServices,
        allLoaded: allServicesLoaded,
        refetch: refetchServices
    } = usePaginatedData<ClusterGroupServices>({
        endpoint: `/cluster-groups/${id}/service-definitions`,
        enabled: !!id,
        keyExtractor: (item) => item.service_definition_id,
    });

    const {
        data: clusters = [],
        isLoading: loadingClusters,
        isLoadingMore: loadingMoreClusters,
        allLoaded: allClustersLoaded,
        refetch: refetchClusters
    } = usePaginatedData<ClusterGroupClusterAssociation>({
        endpoint: `/cluster-groups/${id}/clusters`,
        enabled: !!id,
        keyExtractor: (item) => item.id,
    });

    // Mutations
    const deleteClusterGroup = useDeleteClusterGroup();
    const updateClusterGroup = useUpdateClusterGroup();
    const subscribeClusters = useSubscribeClustersToGroup();
    const unsubscribeCluster = useUnsubscribeClusterFromGroup();
    const subscribeServices = useSubscribeServiceDefinitionsToGroup();
    const unsubscribeService = useUnsubscribeServiceDefinitionFromGroup();

    const handleRefreshAll = () => {
        refetchGroup();
        refetchServices();
        refetchClusters();
    };

    const handleDelete = async () => {
        try {
            await deleteClusterGroup.mutateAsync(id!);
            navigate('/cluster-groups');
        } catch (err) {
            console.error('Failed to delete cluster group:', err);
        }
    };

    const handleEdit = async (data: { name: string; priority: number }) => {
        try {
            await updateClusterGroup.mutateAsync({ id: id!, ...data });
            setShowEditModal(false);
            refetchGroup();
        } catch (err) {
            console.error('Failed to update cluster group:', err);
        }
    };

    const handleAddClusters = async (clusterIds: string[], clusterNames: string[]) => {
        try {
            setAddClustersError(null);
            await subscribeClusters.mutateAsync({ groupId: id!, clusterIds });
            setShowAddClustersModal(false);
            refetchClusters();
        } catch (err) {
            console.error('Failed to add clusters:', err);

            const prefix = clusterNames.length
                ? `Couldn't add ${clusterNames.slice(0, 5).join(', ')}${clusterNames.length > 5 ? '…' : ''}. `
                : "Couldn't add the selected clusters. ";

            const rawMessage = getUserFriendlyApiError(
                err,
                'They may already be associated, or you may not have permission.'
            );
            const resolvedMessage = await resolveServiceIdsInErrorMessage(rawMessage, services);

            setAddClustersError(
                prefix + resolvedMessage
            );
        }
    };

    const handleRemoveCluster = async () => {
        if (!clusterToRemove) return;
        try {
            await unsubscribeCluster.mutateAsync({ clusterId: clusterToRemove.id, groupId: id! });
            setClusterToRemove(null);
            refetchClusters();
        } catch (err) {
            console.error('Failed to remove cluster:', err);
        }
    };

    const handleAddServices = async (serviceDefinitionIds: string[], serviceNames: string[]) => {
        try {
            setAddServicesError(null);
            await subscribeServices.mutateAsync({ groupId: id!, serviceDefinitionIds });
            setShowAddServicesModal(false);
            refetchServices();
        } catch (err) {
            console.error('Failed to add services:', err);

            const prefix = serviceNames.length
                ? `Couldn't add ${serviceNames.slice(0, 5).join(', ')}${serviceNames.length > 5 ? '…' : ''}. `
                : "Couldn't add the selected services. ";

            const rawMessage = getUserFriendlyApiError(
                err,
                'They may already be in the group, or the repo/service may be invalid.'
            );
            const resolvedMessage = await resolveServiceIdsInErrorMessage(rawMessage, services);

            setAddServicesError(
                prefix + resolvedMessage
            );
        }
    };

    const handleRemoveService = async () => {
        if (!serviceToRemove) return;
        try {
            await unsubscribeService.mutateAsync({ groupId: id!, serviceDefinitionId: serviceToRemove.service_definition_id });
            setServiceToRemove(null);
            refetchServices();
        } catch (err) {
            console.error('Failed to remove service:', err);
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                <span className="ml-3 text-gray-600 dark:text-gray-400">Loading cluster group...</span>
            </div>
        );
    }

    if (isError || !group) {
        return (
            <div className="p-4">
                <Alert
                    type="error"
                    title="Failed to load cluster group"
                    message={error instanceof Error ? error.message : 'Cluster group not found'}
                />
                <button
                    onClick={() => navigate('/cluster-groups')}
                    className="mt-4 inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Cluster Groups
                </button>
            </div>
        );
    }

    const serviceColumns = [
        {
            key: 'service_name',
            header: 'Service',
            sortable: true,
            getValue: (s: ClusterGroupServices) => s.service_name,
            render: (s: ClusterGroupServices) => (
                <Link
                    to={`/services/${s.service_definition_id}`}
                    className="font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    {s.service_name}
                </Link>
            ),
        },
        {
            key: 'repo',
            header: 'Repository',
            sortable: true,
            getValue: (s: ClusterGroupServices) => `${s.org}/${s.repo}`,
            render: (s: ClusterGroupServices) => (
                <Link
                    to={`/repos/${s.repo_id}`}
                    className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                >
                    {s.org}/{s.repo}
                </Link>
            ),
        },
        {
            key: 'branch',
            header: 'Branch',
            sortable: true,
            getValue: (s: ClusterGroupServices) => s.branch,
            render: (s: ClusterGroupServices) => (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    {s.branch}
                </span>
            ),
        },
        {
            key: 'actions',
            header: '',
            render: (s: ClusterGroupServices) => (
                <button
                    onClick={() => setServiceToRemove(s)}
                    className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                    title="Remove from group"
                >
                    <X className="w-4 h-4" />
                </button>
            ),
        },
    ];

    const associatedClusterColumns = [
        {
            key: 'name',
            header: 'Cluster',
            sortable: true,
            getValue: (c: ClusterGroupClusterAssociation) => c.name,
            render: (c: ClusterGroupClusterAssociation) => (
                <Link
                    to={`/clusters/${c.id}`}
                    className="font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    {c.name}
                </Link>
            ),
        },
        {
            key: 'status',
            header: 'Status',
            render: () => (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    Associated
                </span>
            ),
        },
        {
            key: 'actions',
            header: '',
            render: (c: ClusterGroupClusterAssociation) => (
                <button
                    onClick={() => setClusterToRemove(c)}
                    className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                    title="Remove from group"
                >
                    <X className="w-4 h-4" />
                </button>
            ),
        },
    ];

    const associatedClusters = clusters.filter(c => c.associated);
    const unassociatedClusters = clusters.filter(c => !c.associated);

    return (
        <div className="space-y-6">
            {/* Delete Confirmation Modal */}
            <ConfirmModal
                isOpen={showDeleteModal}
                onClose={() => setShowDeleteModal(false)}
                onConfirm={handleDelete}
                title="Delete Cluster Group"
                message={`Are you sure you want to delete cluster group "${group.name}"? This will unsubscribe all associated clusters but will not delete the clusters themselves.`}
                confirmText={deleteClusterGroup.isPending ? 'Deleting...' : 'Delete Group'}
                variant="danger"
                isLoading={deleteClusterGroup.isPending}
            />

            {/* Edit Group Modal */}
            <EditGroupModal
                isOpen={showEditModal}
                onClose={() => setShowEditModal(false)}
                onSubmit={handleEdit}
                isPending={updateClusterGroup.isPending}
                initialName={group.name}
                initialPriority={group.priority}
            />

            {/* Add Clusters Modal */}
            <AddClustersModal
                isOpen={showAddClustersModal}
                onClose={() => {
                    setAddClustersError(null);
                    setShowAddClustersModal(false);
                }}
                onSubmit={handleAddClusters}
                isPending={subscribeClusters.isPending}
                groupId={id!}
                submitError={addClustersError}
                onDismissSubmitError={() => setAddClustersError(null)}
            />

            {/* Remove Cluster Confirmation Modal */}
            <ConfirmModal
                isOpen={!!clusterToRemove}
                onClose={() => setClusterToRemove(null)}
                onConfirm={handleRemoveCluster}
                title="Remove Cluster from Group"
                message={`Are you sure you want to remove cluster "${clusterToRemove?.name}" from this group? The cluster will no longer receive deployments from this group's services.`}
                confirmText={unsubscribeCluster.isPending ? 'Removing...' : 'Remove Cluster'}
                variant="warning"
                isLoading={unsubscribeCluster.isPending}
            />

            {/* Add Services Modal */}
            <AddServicesModal
                isOpen={showAddServicesModal}
                onClose={() => {
                    setAddServicesError(null);
                    setShowAddServicesModal(false);
                }}
                onSubmit={handleAddServices}
                isPending={subscribeServices.isPending}
                groupId={id!}
                submitError={addServicesError}
                onDismissSubmitError={() => setAddServicesError(null)}
            />

            {/* Remove Service Confirmation Modal */}
            <ConfirmModal
                isOpen={!!serviceToRemove}
                onClose={() => setServiceToRemove(null)}
                onConfirm={handleRemoveService}
                title="Remove Service from Group"
                message={`Are you sure you want to remove service "${serviceToRemove?.service_name}" from this group? The service will no longer be deployed to clusters in this group.`}
                confirmText={unsubscribeService.isPending ? 'Removing...' : 'Remove Service'}
                variant="warning"
                isLoading={unsubscribeService.isPending}
            />

            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate('/cluster-groups')}
                    className="inline-flex items-center text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Cluster Groups
                </button>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setShowEditModal(true)}
                        className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        <Edit className="w-4 h-4 mr-2" />
                        Edit
                    </button>
                    <button
                        onClick={handleRefreshAll}
                        className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        <RefreshCw className="w-4 h-4 mr-2" />
                        Refresh
                    </button>
                    <button
                        onClick={() => setShowDeleteModal(true)}
                        disabled={deleteClusterGroup.isPending}
                        className="inline-flex items-center px-3 py-2 border border-red-300 dark:border-red-700 text-sm font-medium rounded-md text-red-700 dark:text-red-400 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50"
                    >
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete
                    </button>
                </div>
            </div>

            <PageHeader
                title={group.name}
                description={`Cluster Group ID: ${id}`}
            />

            {/* Group Info Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Server className="w-8 h-8 text-blue-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Associated Clusters</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{associatedClusters.length}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Package className="w-8 h-8 text-green-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Services</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{services.length}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                            <span className="text-purple-600 dark:text-purple-300 font-bold">{group.priority}</span>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Priority</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{group.priority}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Associated Clusters Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                            Associated Clusters ({associatedClusters.length})
                        </h3>
                        <button
                            onClick={() => setShowAddClustersModal(true)}
                            disabled={unassociatedClusters.length === 0}
                            className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <Plus className="w-4 h-4 mr-1" />
                            Add Clusters
                        </button>
                    </div>
                </div>
                <DataTable
                    data={associatedClusters}
                    columns={associatedClusterColumns}
                    keyExtractor={(c) => c.id}
                    isLoading={loadingClusters}
                    emptyMessage="No clusters are associated with this group"
                    searchPlaceholder="Search clusters..."
                    isLoadingMore={loadingMoreClusters}
                    allLoaded={allClustersLoaded}
                    totalItems={associatedClusters.length}
                />
            </div>

            {/* Services Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                            Service Definitions ({services.length})
                        </h3>
                        <button
                            onClick={() => setShowAddServicesModal(true)}
                            className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
                        >
                            <Plus className="w-4 h-4 mr-1" />
                            Add Services
                        </button>
                    </div>
                </div>
                <DataTable
                    data={services}
                    columns={serviceColumns}
                    keyExtractor={(s) => s.service_definition_id}
                    isLoading={loadingServices}
                    emptyMessage="No services are deployed to this group"
                    searchPlaceholder="Search services..."
                    isLoadingMore={loadingMoreServices}
                    allLoaded={allServicesLoaded}
                    totalItems={services.length}
                />
            </div>
        </div>
    );
}
