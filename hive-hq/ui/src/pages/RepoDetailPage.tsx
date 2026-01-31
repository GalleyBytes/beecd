import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, ExternalLink, GitBranch, FileCode, Plus, X, Package, Webhook, AlertCircle, CheckCircle, Loader2, Trash2, Clock } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { useRepo, usePaginatedData, useAddRepoBranch, useAddRepoService, useRepoWebhook, useRegisterWebhook, useDeleteWebhook, useWebhookEvents } from '@/hooks';
import type { RepoBranch, ServiceDefinitionData, RepoWebhookEvent } from '@/types';

const GITHUB_URL = 'https://github.com';

// Validate that manifest path template contains all required placeholders
function isValidManifestPathTemplate(template: string): boolean {
    if (!template.trim()) return true; // Empty is valid (optional field)
    return (
        template.includes('{cluster}') &&
        template.includes('{namespace}') &&
        template.includes('{service}')
    );
}

export function RepoDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    // Modal states
    const [showAddBranchModal, setShowAddBranchModal] = useState(false);
    const [showAddServiceModal, setShowAddServiceModal] = useState(false);
    const [newBranchName, setNewBranchName] = useState('');
    const [newServiceName, setNewServiceName] = useState('');
    const [newServiceManifestPath, setNewServiceManifestPath] = useState('');

    // Webhook state
    const [showWebhookModal, setShowWebhookModal] = useState(false);
    const [showDeleteWebhookModal, setShowDeleteWebhookModal] = useState(false);
    const [registerGithubToken, setRegisterGithubToken] = useState('');
    const [deleteGithubToken, setDeleteGithubToken] = useState('');
    const [showWebhookEvents, setShowWebhookEvents] = useState(false);

    const { data: repo, isLoading, isError, error, refetch: refetchRepo } = useRepo(id!);

    // Mutations
    const addBranchMutation = useAddRepoBranch();
    const addServiceMutation = useAddRepoService();
    const registerWebhookMutation = useRegisterWebhook();
    const deleteWebhookMutation = useDeleteWebhook();

    // Webhook data
    const { data: webhook, isLoading: webhookLoading, refetch: refetchWebhook } = useRepoWebhook(id!);
    const { data: webhookEvents = [], isLoading: eventsLoading, refetch: refetchWebhookEvents } = useWebhookEvents(id!, { limit: 10, offset: 0 });

    // Paginated data - loads all pages for proper search
    const {
        data: branches = [],
        isLoading: loadingBranches,
        isLoadingMore: loadingMoreBranches,
        allLoaded: allBranchesLoaded,
        refetch: refetchBranches
    } = usePaginatedData<RepoBranch>({
        endpoint: `/repos/${id}/branches`,
        enabled: !!id,
        keyExtractor: (item) => item.id,
    });

    const {
        data: services = [],
        isLoading: loadingServices,
        isLoadingMore: loadingMoreServices,
        allLoaded: allServicesLoaded,
        refetch: refetchServices
    } = usePaginatedData<ServiceDefinitionData>({
        endpoint: `/repos/${id}/service-definitions`,
        enabled: !!id,
        keyExtractor: (item) => item.service_definition_id,
    });

    const handleRefreshAll = () => {
        refetchRepo();
        refetchBranches();
        refetchServices();
    };

    const handleAddBranch = async () => {
        if (!id || !newBranchName.trim()) return;

        try {
            await addBranchMutation.mutateAsync({ repoId: id, branch: newBranchName.trim() });
            setNewBranchName('');
            setShowAddBranchModal(false);
            refetchBranches();
        } catch (err) {
            console.error('Failed to add branch:', err);
        }
    };

    const handleAddService = async () => {
        if (!id || !newServiceName.trim()) return;

        try {
            // Service names must always be lowercase
            const serviceName = newServiceName.trim().toLowerCase();
            await addServiceMutation.mutateAsync({
                repoId: id,
                name: serviceName,
                manifestPathTemplate: newServiceManifestPath.trim() || undefined,
            });
            setNewServiceName('');
            setNewServiceManifestPath('');
            setShowAddServiceModal(false);
            refetchServices();
        } catch (err) {
            console.error('Failed to add service:', err);
        }
    };

    const handleRegisterWebhook = async () => {
        if (!id || !registerGithubToken.trim()) return;

        try {
            await registerWebhookMutation.mutateAsync({
                repoId: id,
                githubToken: registerGithubToken.trim(),
            });
            setRegisterGithubToken('');
            setShowWebhookModal(false);
            refetchWebhook();
        } catch (err) {
            console.error('Failed to register webhook:', err);
        }
    };

    const handleDeleteWebhook = async () => {
        if (!id) return;

        try {
            await deleteWebhookMutation.mutateAsync({
                repoId: id,
                githubToken: deleteGithubToken.trim() || undefined,
            });
            setDeleteGithubToken('');
            setShowDeleteWebhookModal(false);
            refetchWebhook();
        } catch (err) {
            console.error('Failed to delete webhook:', err);
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
                <span className="ml-3 text-gray-600 dark:text-gray-400">Loading repository...</span>
            </div>
        );
    }

    if (isError || !repo) {
        return (
            <div className="p-4">
                <Alert
                    type="error"
                    title="Failed to load repository"
                    message={error instanceof Error ? error.message : 'Repository not found'}
                />
                <button
                    onClick={() => navigate('/repos')}
                    className="mt-4 inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Repositories
                </button>
            </div>
        );
    }

    const branchColumns = [
        {
            key: 'branch',
            header: 'Branch',
            sortable: true,
            getValue: (b: RepoBranch) => b.branch,
            render: (b: RepoBranch) => (
                <div className="flex items-center">
                    <GitBranch className="w-4 h-4 mr-2 text-gray-400 dark:text-gray-500" />
                    <span className="font-medium dark:text-white">{b.branch}</span>
                    <a
                        href={`${GITHUB_URL}/${b.org}/${b.repo}/tree/${b.branch}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300"
                    >
                        <ExternalLink className="w-4 h-4" />
                    </a>
                </div>
            ),
        },
    ];

    const serviceColumns = [
        {
            key: 'name',
            header: 'Service Name',
            sortable: true,
            getValue: (s: ServiceDefinitionData) => s.name,
            render: (s: ServiceDefinitionData) => (
                <Link
                    to={`/services/name/${s.name}`}
                    className="font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    {s.name}
                </Link>
            ),
        },
        {
            key: 'branch',
            header: 'Branch',
            sortable: true,
            getValue: (s: ServiceDefinitionData) => s.branch,
            render: (s: ServiceDefinitionData) => (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    {s.branch}
                </span>
            ),
        },
        {
            key: 'status',
            header: 'Status',
            render: (s: ServiceDefinitionData) => (
                s.service_deleted_at ? (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                        Deleted
                    </span>
                ) : (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        Active
                    </span>
                )
            ),
        },
    ];

    // Tab display

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate('/repos')}
                    className="inline-flex items-center text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Repositories
                </button>
                <button
                    onClick={handleRefreshAll}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                </button>
            </div>

            <PageHeader
                title={`${repo.org}/${repo.repo}`}
                description={
                    <a
                        href={`${GITHUB_URL}/${repo.org}/${repo.repo}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                    >
                        View on GitHub
                        <ExternalLink className="w-4 h-4 ml-1" />
                    </a>
                }
            />

            {/* Repo Info Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/20 border border-green-200 dark:border-green-800 shadow rounded-lg p-5">
                    <div className="flex items-start">
                        <div className="flex-shrink-0">
                            <FileCode className="w-10 h-10 text-green-600 dark:text-green-400" />
                        </div>
                        <div className="ml-4">
                            <h3 className="text-lg font-semibold text-green-900 dark:text-green-100">
                                Manifest Repository
                            </h3>
                            <p className="mt-1 text-sm text-green-700 dark:text-green-300">
                                Stores rendered Kubernetes manifests that agents deploy to clusters.
                                Services pull their deployment YAML from branches in this repo.
                            </p>
                            <div className="mt-3 flex items-center gap-4 text-sm text-green-600 dark:text-green-400">
                                <span className="flex items-center">
                                    <GitBranch className="w-4 h-4 mr-1" />
                                    {branches.length} branches
                                </span>
                                <span className="flex items-center">
                                    <Package className="w-4 h-4 mr-1" />
                                    {services.length} services
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* GitHub Webhook Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Webhook className="w-5 h-5 text-purple-500" />
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">GitHub Webhook</h3>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                Automatically create service versions when manifests are pushed
                            </p>
                        </div>
                    </div>
                    {!webhook && !webhookLoading && (
                        <button
                            onClick={() => setShowWebhookModal(true)}
                            className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-purple-600 hover:bg-purple-700"
                        >
                            <Plus className="w-4 h-4 mr-1" />
                            Register Webhook
                        </button>
                    )}
                </div>
                <div className="px-4 py-5 sm:px-6">
                    {webhookLoading ? (
                        <div className="flex items-center justify-center py-4">
                            <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
                            <span className="ml-2 text-sm text-gray-500">Loading webhook status...</span>
                        </div>
                    ) : webhook ? (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <CheckCircle className="w-5 h-5 text-green-500" />
                                    <span className="text-sm font-medium text-gray-900 dark:text-gray-100">Webhook Active</span>
                                    {webhook.active ? (
                                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                            Connected
                                        </span>
                                    ) : (
                                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                                            Inactive
                                        </span>
                                    )}
                                </div>
                                <button
                                    onClick={() => setShowDeleteWebhookModal(true)}
                                    disabled={deleteWebhookMutation.isPending}
                                    className="inline-flex items-center text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 disabled:opacity-50"
                                    title="Delete webhook"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                            <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                    <span className="text-gray-500 dark:text-gray-400">Provider Webhook ID:</span>
                                    <span className="ml-2 font-mono text-gray-900 dark:text-gray-100">{webhook.provider_webhook_id}</span>
                                </div>
                                {webhook.last_delivery_at && (
                                    <div>
                                        <span className="text-gray-500 dark:text-gray-400">Last Delivery:</span>
                                        <span className="ml-2 text-gray-900 dark:text-gray-100">
                                            {new Date(webhook.last_delivery_at).toLocaleString()}
                                        </span>
                                    </div>
                                )}
                            </div>
                            {webhook.last_error && (
                                <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-md">
                                    <div className="flex items-start">
                                        <AlertCircle className="w-4 h-4 text-red-500 mt-0.5" />
                                        <div className="ml-2">
                                            <span className="text-sm font-medium text-red-800 dark:text-red-200">Last Error:</span>
                                            <p className="text-sm text-red-700 dark:text-red-300">{webhook.last_error}</p>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Webhook Events */}
                            <div className="mt-4">
                                <button
                                    onClick={() => {
                                        setShowWebhookEvents(!showWebhookEvents);
                                        if (!showWebhookEvents) refetchWebhookEvents();
                                    }}
                                    className="text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                >
                                    {showWebhookEvents ? 'Hide' : 'Show'} Recent Events ({webhookEvents.length})
                                </button>
                                {showWebhookEvents && (
                                    <div className="mt-3 space-y-2">
                                        {eventsLoading ? (
                                            <div className="flex items-center py-2">
                                                <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                                                <span className="ml-2 text-sm text-gray-500">Loading events...</span>
                                            </div>
                                        ) : webhookEvents.length === 0 ? (
                                            <p className="text-sm text-gray-500 dark:text-gray-400 py-2">No webhook events yet</p>
                                        ) : (
                                            <div className="max-h-64 overflow-y-auto">
                                                {webhookEvents.map((event: RepoWebhookEvent) => (
                                                    <div key={event.id} className="p-2 bg-gray-50 dark:bg-gray-700/50 rounded mb-2 text-sm">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-medium text-gray-900 dark:text-gray-100">{event.event_type}</span>
                                                                {event.ref_name && (
                                                                    <span className="text-xs text-gray-500 dark:text-gray-400">
                                                                        {event.ref_name}
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                                                                <Clock className="w-3 h-3 mr-1" />
                                                                {new Date(event.created_at).toLocaleString()}
                                                            </div>
                                                        </div>
                                                        {event.after_sha && (
                                                            <div className="mt-1 text-xs text-gray-500 dark:text-gray-400 font-mono">
                                                                SHA: {event.after_sha.slice(0, 7)}
                                                                {event.pusher && <span className="ml-2">by {event.pusher}</span>}
                                                            </div>
                                                        )}
                                                        {event.updated_service_versions && event.updated_service_versions.length > 0 && (
                                                            <div className="mt-1 text-xs text-green-600 dark:text-green-400">
                                                                ✓ Updated {event.updated_service_versions.length} service version(s)
                                                            </div>
                                                        )}
                                                        {event.matched_paths && event.matched_paths.length > 0 && (
                                                            <div className="mt-1 text-xs text-blue-600 dark:text-blue-400">
                                                                Matched: {event.matched_paths.join(', ')}
                                                            </div>
                                                        )}
                                                        {(!event.matched_paths || event.matched_paths.length === 0) && event.processed_at && (
                                                            <div className="mt-1 text-xs text-yellow-600 dark:text-yellow-400">
                                                                ⚠ No paths matched - check manifest_path_template
                                                            </div>
                                                        )}
                                                        {event.processing_error && (
                                                            <div className="mt-1 text-xs text-red-600 dark:text-red-400">
                                                                ✗ {event.processing_error}
                                                            </div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        <div className="text-center py-4">
                            <Webhook className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-600 mb-2" />
                            <p className="text-gray-500 dark:text-gray-400">No webhook registered</p>
                            <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
                                Register a GitHub webhook to automatically create service versions when manifests are pushed.
                            </p>
                        </div>
                    )}
                </div>
            </div>

            {/* Branches Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                Manifest Branches
                            </h3>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                Branches containing deployable Kubernetes manifests
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                                {branches.length} branches
                            </span>
                            <button
                                onClick={() => setShowAddBranchModal(true)}
                                className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 dark:bg-green-500 dark:hover:bg-green-600 transition-colors"
                            >
                                <Plus className="w-4 h-4 mr-1" />
                                Add Branch
                            </button>
                        </div>
                    </div>
                </div>
                <DataTable
                    data={branches}
                    columns={branchColumns}
                    keyExtractor={(b) => b.id}
                    isLoading={loadingBranches}
                    emptyMessage="No branches configured for this repository"
                    searchPlaceholder="Search branches..."
                    isLoadingMore={loadingMoreBranches}
                    allLoaded={allBranchesLoaded}
                    totalItems={branches.length}
                />
            </div>

            {/* Services Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                Service Definitions
                            </h3>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                Services that deploy manifests from this repository (applies to all branches)
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                                {services.length} services
                            </span>
                            <button
                                onClick={() => setShowAddServiceModal(true)}
                                className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 dark:bg-green-500 dark:hover:bg-green-600 transition-colors"
                            >
                                <Plus className="w-4 h-4 mr-1" />
                                Add Service
                            </button>
                        </div>
                    </div>
                </div>
                <DataTable
                    data={services}
                    columns={serviceColumns}
                    keyExtractor={(s) => s.service_definition_id}
                    isLoading={loadingServices}
                    emptyMessage="No service definitions found in this repository"
                    searchPlaceholder="Search services..."
                    isLoadingMore={loadingMoreServices}
                    allLoaded={allServicesLoaded}
                    totalItems={services.length}
                />
            </div>

            {/* Add Branch Modal */}
            {showAddBranchModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={() => setShowAddBranchModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                    Add Branch
                                </h3>
                                <button
                                    onClick={() => setShowAddBranchModal(false)}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                Add a branch from <strong>{repo?.org}/{repo?.repo}</strong> to track for manifest deployments.
                            </p>
                            <div className="mb-4">
                                <label htmlFor="branchName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                    Branch Name
                                </label>
                                <input
                                    type="text"
                                    id="branchName"
                                    value={newBranchName}
                                    onChange={(e) => setNewBranchName(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleAddBranch()}
                                    placeholder="e.g., main, develop, feature/xyz"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white"
                                    autoFocus
                                />
                            </div>
                            {addBranchMutation.isError && (
                                <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to add branch. It may already exist or be invalid.
                                    </p>
                                </div>
                            )}
                            <div className="flex justify-end gap-3">
                                <button
                                    onClick={() => setShowAddBranchModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleAddBranch}
                                    disabled={!newBranchName.trim() || addBranchMutation.isPending}
                                    className="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {addBranchMutation.isPending ? 'Adding...' : 'Add Branch'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Add Service Modal */}
            {showAddServiceModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={() => setShowAddServiceModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-lg w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                    Add Service
                                </h3>
                                <button
                                    onClick={() => setShowAddServiceModal(false)}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                Add a service definition that will be available across <strong>all branches</strong> of this repository.
                            </p>
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="serviceName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Service Name <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        id="serviceName"
                                        value={newServiceName}
                                        onChange={(e) => setNewServiceName(e.target.value.toLowerCase())}
                                        placeholder="e.g., api-gateway, user-service"
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white lowercase"
                                        autoFocus
                                    />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        Service names are always lowercase
                                    </p>
                                </div>
                                <div>
                                    <label htmlFor="manifestPath" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Manifest Path Template
                                    </label>
                                    <input
                                        type="text"
                                        id="manifestPath"
                                        value={newServiceManifestPath}
                                        onChange={(e) => setNewServiceManifestPath(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && isValidManifestPathTemplate(newServiceManifestPath) && handleAddService()}
                                        placeholder={'{cluster}/manifests/{namespace}/{service}/{service}.yaml'}
                                        className={`w-full px-3 py-2 border rounded-md shadow-sm focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white font-mono text-sm ${newServiceManifestPath.trim() && !isValidManifestPathTemplate(newServiceManifestPath)
                                                ? 'border-red-300 dark:border-red-600'
                                                : 'border-gray-300 dark:border-gray-600'
                                            }`}
                                    />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        Path in git to pull manifests from. Use <code className="bg-gray-100 dark:bg-gray-600 px-1 rounded">{'{cluster}'}</code>, <code className="bg-gray-100 dark:bg-gray-600 px-1 rounded">{'{namespace}'}</code>, <code className="bg-gray-100 dark:bg-gray-600 px-1 rounded">{'{service}'}</code> as placeholders.
                                    </p>
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        • Ends with <code className="bg-gray-100 dark:bg-gray-600 px-1 rounded">.yaml</code> → watches a single file<br />
                                        • Directory path → watches all <code className="bg-gray-100 dark:bg-gray-600 px-1 rounded">*.yaml</code> files
                                    </p>
                                    {newServiceManifestPath.trim() && !isValidManifestPathTemplate(newServiceManifestPath) && (
                                        <p className="mt-2 text-xs text-red-600 dark:text-red-400">
                                            ⚠ Path must include all three placeholders: <code className="bg-red-100 dark:bg-red-900/30 px-1 rounded">{'{cluster}'}</code>, <code className="bg-red-100 dark:bg-red-900/30 px-1 rounded">{'{namespace}'}</code>, and <code className="bg-red-100 dark:bg-red-900/30 px-1 rounded">{'{service}'}</code>
                                        </p>
                                    )}
                                </div>
                            </div>
                            {addServiceMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to add service. It may already exist or be invalid.
                                    </p>
                                </div>
                            )}
                            <div className="flex justify-end gap-3 mt-6">
                                <button
                                    onClick={() => setShowAddServiceModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleAddService}
                                    disabled={!newServiceName.trim() || addServiceMutation.isPending || !isValidManifestPathTemplate(newServiceManifestPath)}
                                    className="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {addServiceMutation.isPending ? 'Adding...' : 'Add Service'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Register Webhook Modal */}
            {showWebhookModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => setShowWebhookModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <Webhook className="w-5 h-5 text-purple-500" />
                                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">Register GitHub Webhook</h3>
                                </div>
                                <button
                                    onClick={() => setShowWebhookModal(false)}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                This will register a webhook on <strong>{repo?.org}/{repo?.repo}</strong> to receive push events.
                                When files matching service path templates are pushed, service versions will be automatically created.
                            </p>
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="githubToken" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        GitHub Personal Access Token <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="password"
                                        id="githubToken"
                                        value={registerGithubToken}
                                        onChange={(e) => setRegisterGithubToken(e.target.value)}
                                        placeholder="ghp_xxxxxxxxxxxx"
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500 dark:bg-gray-700 dark:text-white font-mono"
                                        autoFocus
                                    />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        Token needs <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">repo</code> or <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">admin:repo_hook</code> scope
                                    </p>
                                </div>
                                <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-md">
                                    <p className="text-xs text-blue-800 dark:text-blue-200">
                                        <strong>Note:</strong> Your token is only used to create the webhook and is not stored.
                                        A unique secret is generated for webhook signature verification.
                                    </p>
                                </div>
                            </div>
                            {registerWebhookMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to register webhook. Check that your token has the required permissions and the repository is accessible.
                                    </p>
                                </div>
                            )}
                            <div className="mt-6 flex justify-end gap-3">
                                <button
                                    onClick={() => {
                                        setShowWebhookModal(false);
                                        setRegisterGithubToken('');
                                    }}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleRegisterWebhook}
                                    disabled={!registerGithubToken.trim() || registerWebhookMutation.isPending}
                                    className="px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {registerWebhookMutation.isPending ? 'Registering...' : 'Register Webhook'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Delete Webhook Modal */}
            {showDeleteWebhookModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => setShowDeleteWebhookModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <Trash2 className="w-5 h-5 text-red-500" />
                                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">Delete GitHub Webhook</h3>
                                </div>
                                <button
                                    onClick={() => setShowDeleteWebhookModal(false)}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>

                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                This will delete the webhook for <strong>{repo?.org}/{repo?.repo}</strong>.
                                Service versions will no longer be automatically created from pushes.
                            </p>

                            <div className="space-y-4">
                                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-xs text-red-800 dark:text-red-200">
                                        <strong>Warning:</strong> this disables automatic version creation from GitHub push events.
                                    </p>
                                </div>

                                <div>
                                    <label htmlFor="githubTokenDelete" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        GitHub Personal Access Token <span className="text-gray-400">(optional)</span>
                                    </label>
                                    <input
                                        type="password"
                                        id="githubTokenDelete"
                                        value={deleteGithubToken}
                                        onChange={(e) => setDeleteGithubToken(e.target.value)}
                                        placeholder="ghp_xxxxxxxxxxxx"
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white font-mono"
                                        autoFocus
                                    />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        If provided, BeeCD will also remove the webhook from GitHub (requires <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">repo</code> or <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">admin:repo_hook</code> scope).
                                    </p>
                                </div>
                            </div>

                            {deleteWebhookMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to delete webhook. Check that your token has the required permissions and the repository is accessible.
                                    </p>
                                </div>
                            )}

                            <div className="mt-6 flex justify-end gap-3">
                                <button
                                    onClick={() => {
                                        setShowDeleteWebhookModal(false);
                                        setDeleteGithubToken('');
                                    }}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleDeleteWebhook}
                                    disabled={deleteWebhookMutation.isPending}
                                    className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {deleteWebhookMutation.isPending ? 'Deleting...' : 'Delete Webhook'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
