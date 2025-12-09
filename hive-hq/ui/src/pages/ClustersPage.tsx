import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Plus, AlertCircle, X, Copy, Check, AlertTriangle } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { usePaginatedData, useCreateCluster } from '@/hooks';
import type { Cluster } from '@/types';
import apiClient from '@/lib/api-client';

export function ClustersPage() {
    const navigate = useNavigate();
    const { data, isLoading, isLoadingMore, allLoaded, error, refetch } = usePaginatedData<Cluster>({
        endpoint: '/clusters',
        keyExtractor: (cluster) => cluster.id,
    });
    const isError = !!error;
    const isFetching = isLoading || isLoadingMore;

    // Add Cluster modal state
    const [showAddClusterModal, setShowAddClusterModal] = useState(false);
    const [clusterName, setClusterName] = useState('');
    const [namespace, setNamespace] = useState('beecd');
    const [grpcAddress, setGrpcAddress] = useState('hive.example.com:443');
    const [grpcTls, setGrpcTls] = useState(false);
    const [image, setImage] = useState('ghcr.io/beecd/agent:latest');
    const [grpcAddressTouched, setGrpcAddressTouched] = useState(false);
    const [grpcTlsTouched, setGrpcTlsTouched] = useState(false);
    const [imageTouched, setImageTouched] = useState(false);
    const [generatedManifest, setGeneratedManifest] = useState<string | null>(null);
    const [createdClusterId, setCreatedClusterId] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [showRegeneratePrompt, setShowRegeneratePrompt] = useState(false);

    const createClusterMutation = useCreateCluster();

    useEffect(() => {
        if (!showAddClusterModal) return;

        let cancelled = false;
        (async () => {
            try {
                const response = await apiClient.get<{
                    grpc_address?: string | null;
                    grpc_tls?: boolean | null;
                    agent_image?: string | null;
                }>('/cluster-defaults');

                if (cancelled) return;
                const defaults = response.data;

                if (!grpcAddressTouched && defaults.grpc_address) {
                    setGrpcAddress(defaults.grpc_address);
                }
                if (!grpcTlsTouched && typeof defaults.grpc_tls === 'boolean') {
                    setGrpcTls(defaults.grpc_tls);
                }
                if (!imageTouched && defaults.agent_image) {
                    setImage(defaults.agent_image);
                }
            } catch {
                // Keep local defaults if API defaults aren't configured/reachable.
            }
        })();

        return () => {
            cancelled = true;
        };
    }, [showAddClusterModal, grpcAddressTouched, grpcTlsTouched, imageTouched]);

    const validateGrpcHostPort = (value: string): string | null => {
        const trimmed = value.trim();
        if (!trimmed) return 'Hive gRPC Address is required.';
        if (trimmed.includes('://')) return 'Do not include a scheme (http:// or https://). Use host:port.';
        if (/[\s]/.test(trimmed)) return 'Address must not contain spaces.';
        if (trimmed.includes('/')) return 'Address must be host:port only.';

        // IPv6 should be provided as [::1]:443
        if (trimmed.startsWith('[')) {
            if (!/^\[[0-9a-fA-F:]+\]:\d+$/.test(trimmed)) {
                return 'Invalid IPv6 address format. Use [::1]:443.';
            }
            const portStr = trimmed.split(']:')[1];
            const port = Number(portStr);
            if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Port must be between 1 and 65535.';
            return null;
        }

        const parts = trimmed.split(':');
        if (parts.length !== 2) return 'Use host:port format.';
        const [host, portStr] = parts;
        if (!host) return 'Host is required.';
        const port = Number(portStr);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Port must be between 1 and 65535.';
        return null;
    };

    const grpcAddressError = validateGrpcHostPort(grpcAddress);

    const handleAddCluster = async (regenerateSecret = false) => {
        if (!clusterName.trim()) return;

        try {
            const result = await createClusterMutation.mutateAsync({
                name: clusterName.trim(),
                context: {
                    agent_name: clusterName.trim(),
                    namespace: namespace,
                    grpc_address: grpcAddress,
                    grpc_tls: grpcTls,
                    image: image,
                },
                regenerateSecret,
            });

            setCreatedClusterId(result.cluster.id);

            // If user already existed and we didn't request regeneration, show prompt
            if (result.user_existed && (!result.manifest || result.manifest_is_placeholder)) {
                setShowRegeneratePrompt(true);
                return;
            }

            // We have a manifest (either new user or regenerated)
            if (result.manifest) {
                setGeneratedManifest(result.manifest);
                setShowRegeneratePrompt(false);
            }
        } catch (err) {
            console.error('Failed to create cluster:', err);
        }
    };

    const handleRegenerateSecret = () => {
        handleAddCluster(true);
    };

    const handleSkipRegenerate = () => {
        // User chose not to regenerate, close the modal
        handleCloseModal();
    };

    const handleCloseModal = () => {
        setShowAddClusterModal(false);
        setClusterName('');
        setNamespace('beecd');
        setGrpcAddress('hive.example.com:443');
        setImage('ghcr.io/beecd/agent:latest');
        setGeneratedManifest(null);
        setCreatedClusterId(null);
        setCopied(false);
        setShowRegeneratePrompt(false);
        refetch();
    };

    const handleCopyManifest = async () => {
        if (generatedManifest) {
            await navigator.clipboard.writeText(generatedManifest);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    const handleGoToCluster = () => {
        if (createdClusterId) {
            navigate(`/clusters/${createdClusterId}`);
        }
        handleCloseModal();
    };

    const isPending = createClusterMutation.isPending;

    const columns = [
        {
            key: 'name',
            header: 'Name',
            sortable: true,
            getValue: (cluster: Cluster) => cluster.name,
            render: (cluster: Cluster) => (
                <span className="font-medium text-blue-600 dark:text-blue-400">{cluster.name}</span>
            ),
        },
        {
            key: 'version',
            header: 'Agent Version',
            sortable: true,
            getValue: (cluster: Cluster) => cluster.version,
            render: (cluster: Cluster) => (
                <span className="text-gray-600 dark:text-gray-400">{cluster.version || '-'}</span>
            ),
        },
        {
            key: 'kubernetes_version',
            header: 'Kubernetes Version',
            sortable: true,
            getValue: (cluster: Cluster) => cluster.kubernetes_version,
            render: (cluster: Cluster) => (
                <span className="text-gray-600 dark:text-gray-400">{cluster.kubernetes_version || '-'}</span>
            ),
        },
        {
            key: 'metadata',
            header: 'Metadata',
            sortable: false,
            searchable: true,
            render: (cluster: Cluster) => (
                <span className="text-gray-500 dark:text-gray-400 text-xs truncate max-w-xs block">
                    {cluster.metadata || '-'}
                </span>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Clusters"
                description="Manage your Kubernetes clusters connected to BeeCD"
                actions={
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setShowAddClusterModal(true)}
                            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        >
                            <Plus className="w-4 h-4 mr-2" />
                            Add Cluster
                        </button>
                        <button
                            onClick={() => refetch()}
                            disabled={isFetching}
                            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                        >
                            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
                            Refresh
                        </button>
                    </div>
                }
            />

            {isError && (
                <div className="mb-4">
                    <Alert
                        type="error"
                        title="Failed to load clusters"
                        message={error instanceof Error ? error.message : 'An unknown error occurred'}
                    />
                </div>
            )}

            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <DataTable
                    data={data}
                    columns={columns}
                    keyExtractor={(cluster) => cluster.id}
                    isLoading={isLoading}
                    isLoadingMore={isLoadingMore}
                    allLoaded={allLoaded}
                    emptyMessage="No clusters found. Click 'Add Cluster' to get started."
                    onRowClick={(cluster) => navigate(`/clusters/${cluster.id}`)}
                    searchPlaceholder="Search clusters..."
                />
            </div>

            {/* Add Cluster Modal */}
            {showAddClusterModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={handleCloseModal} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                    {generatedManifest ? 'Agent Manifest Generated' : showRegeneratePrompt ? 'Agent Credentials Exist' : 'Add Cluster'}
                                </h3>
                                <button
                                    onClick={handleCloseModal}
                                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>

                            {!showRegeneratePrompt && !generatedManifest && (
                                <div className="mb-4 rounded-md bg-blue-50 dark:bg-blue-900/20 p-4 border border-blue-200 dark:border-blue-800">
                                    <div className="flex">
                                        <div className="flex-shrink-0">
                                            <AlertCircle className="h-5 w-5 text-blue-400" />
                                        </div>
                                        <div className="ml-3">
                                            <h4 className="text-sm font-medium text-blue-800 dark:text-blue-200">
                                                Agent deployment required
                                            </h4>
                                            <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                                                After adding a cluster, deploy the generated agent manifest to your Kubernetes cluster.
                                                The agent will connect automatically and report cluster status.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {showRegeneratePrompt ? (
                                <>
                                    <div className="mb-4 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md">
                                        <div className="flex">
                                            <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                                            <div className="ml-3">
                                                <h4 className="text-sm font-medium text-amber-800 dark:text-amber-200">
                                                    Agent credentials already exist for "{clusterName}"
                                                </h4>
                                                <p className="mt-2 text-sm text-amber-700 dark:text-amber-300">
                                                    An agent user with credentials for this cluster already exists. You can:
                                                </p>
                                                <ul className="mt-2 text-sm text-amber-700 dark:text-amber-300 list-disc list-inside space-y-1">
                                                    <li>Skip and use the existing credentials (if you still have the manifest)</li>
                                                    <li>Regenerate the secret to get a new manifest (the old secret will be invalidated)</li>
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="mt-6 flex justify-end gap-3">
                                        <button
                                            onClick={handleSkipRegenerate}
                                            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                        >
                                            Skip
                                        </button>
                                        <button
                                            onClick={handleRegenerateSecret}
                                            disabled={isPending}
                                            className="px-4 py-2 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                        >
                                            {isPending ? 'Regenerating...' : 'Regenerate Secret'}
                                        </button>
                                    </div>
                                </>
                            ) : !generatedManifest ? (
                                <>
                                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                        Create a new cluster and generate the agent deployment manifest.
                                    </p>
                                    <div className="space-y-4">
                                        <div>
                                            <label htmlFor="clusterName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                                Cluster Name <span className="text-red-500">*</span>
                                            </label>
                                            <input
                                                type="text"
                                                id="clusterName"
                                                value={clusterName}
                                                onChange={(e) => setClusterName(e.target.value)}
                                                placeholder="e.g., production-cluster"
                                                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
                                                autoFocus
                                            />
                                        </div>
                                        <div>
                                            <label htmlFor="namespace" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                                Agent Namespace
                                            </label>
                                            <input
                                                type="text"
                                                id="namespace"
                                                value={namespace}
                                                onChange={(e) => setNamespace(e.target.value)}
                                                placeholder="beecd"
                                                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
                                            />
                                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                Kubernetes namespace where the agent will be deployed
                                            </p>
                                        </div>
                                        <div>
                                            <label htmlFor="grpcAddress" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                                Hive gRPC Address
                                            </label>
                                            <input
                                                type="text"
                                                id="grpcAddress"
                                                value={grpcAddress}
                                                onChange={(e) => {
                                                    setGrpcAddressTouched(true);
                                                    setGrpcAddress(e.target.value);
                                                }}
                                                placeholder="hive.example.com:443"
                                                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
                                            />
                                            <div className="mt-2 flex items-center gap-4">
                                                <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                                                    <input
                                                        type="radio"
                                                        name="grpcTls"
                                                        checked={grpcTls}
                                                        onChange={() => {
                                                            setGrpcTlsTouched(true);
                                                            setGrpcTls(true);
                                                        }}
                                                        className="h-4 w-4 text-blue-600 focus:ring-blue-500"
                                                    />
                                                    TLS
                                                </label>
                                                <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                                                    <input
                                                        type="radio"
                                                        name="grpcTls"
                                                        checked={!grpcTls}
                                                        onChange={() => {
                                                            setGrpcTlsTouched(true);
                                                            setGrpcTls(false);
                                                        }}
                                                        className="h-4 w-4 text-blue-600 focus:ring-blue-500"
                                                    />
                                                    Plaintext
                                                </label>
                                            </div>
                                            {grpcAddressError ? (
                                                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{grpcAddressError}</p>
                                            ) : (
                                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                    Use host:port (no scheme). The agent will construct the connection string.
                                                </p>
                                            )}
                                        </div>
                                        <div>
                                            <label htmlFor="image" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                                Agent Image
                                            </label>
                                            <input
                                                type="text"
                                                id="image"
                                                value={image}
                                                onChange={(e) => {
                                                    setImageTouched(true);
                                                    setImage(e.target.value);
                                                }}
                                                placeholder="ghcr.io/beecd/agent:latest"
                                                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white font-mono text-sm"
                                            />
                                        </div>
                                    </div>
                                    {createClusterMutation.isError && (
                                        <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                            <p className="text-sm text-red-600 dark:text-red-400">
                                                {(() => {
                                                    const error = createClusterMutation.error;
                                                    if (error && 'response' in error) {
                                                        const axiosError = error as { response?: { data?: string; status?: number } };
                                                        if (axiosError.response?.data) {
                                                            return String(axiosError.response.data);
                                                        }
                                                    }
                                                    return 'Failed to create cluster. Please try again.';
                                                })()}
                                            </p>
                                        </div>
                                    )}
                                    <div className="mt-6 flex justify-end gap-3">
                                        <button
                                            onClick={handleCloseModal}
                                            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={() => handleAddCluster(false)}
                                            disabled={!clusterName.trim() || !!grpcAddressError || isPending}
                                            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                        >
                                            {isPending ? 'Creating...' : 'Create & Generate Manifest'}
                                        </button>
                                    </div>
                                </>
                            ) : (
                                <>
                                    <div className="mb-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-md">
                                        <p className="text-sm text-green-700 dark:text-green-300">
                                            <strong>Cluster "{clusterName}" created successfully!</strong> Deploy this manifest to your Kubernetes cluster to connect the agent.
                                        </p>
                                    </div>
                                    <div className="relative">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                                Agent Kubernetes Manifest
                                            </span>
                                            <button
                                                onClick={handleCopyManifest}
                                                className="inline-flex items-center px-3 py-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                                            >
                                                {copied ? (
                                                    <>
                                                        <Check className="w-4 h-4 mr-1" />
                                                        Copied!
                                                    </>
                                                ) : (
                                                    <>
                                                        <Copy className="w-4 h-4 mr-1" />
                                                        Copy to Clipboard
                                                    </>
                                                )}
                                            </button>
                                        </div>
                                        <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-xs overflow-x-auto max-h-80">
                                            {generatedManifest}
                                        </pre>
                                    </div>
                                    <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
                                        Apply this manifest with: <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">kubectl apply -f agent.yaml</code>
                                    </p>
                                    <div className="mt-6 flex justify-end gap-3">
                                        <button
                                            onClick={handleCloseModal}
                                            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                        >
                                            Close
                                        </button>
                                        <button
                                            onClick={handleGoToCluster}
                                            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors"
                                        >
                                            Go to Cluster
                                        </button>
                                    </div>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
