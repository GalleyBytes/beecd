import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Server, Layers, AlertTriangle, Activity, Trash2, FileCode, X, Package, Eye, GitCompare } from 'lucide-react';
import { PageHeader, DataTable, Alert, Modal, ConfirmModal } from '@/components';
import {
    useCluster,
    useClusterErrors,
    useClusterHeartbeat,
    useClusterGroups_ForCluster,
    useDeleteCluster,
    useAddClusterNamespaces,
    useInitNamespaceServices,
    useRemoveServiceFromNamespace,
    useCreateCluster,
    usePaginatedData,
} from '@/hooks';
import type { ClusterNamespaceServicesData, ReleaseStatus, HiveError, ClusterClusterGroups, ClusterServiceDefinitions } from '@/types';
import apiClient from '@/lib/api-client';

function formatRelativeTime(dateString: string): string {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

function StatusBadge({ status }: { status: string }) {
    const statusColors: Record<string, string> = {
        'InstalledUpToDate': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        'Installed': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        'Installing': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        'DriftRepairsInstalling': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        'PendingApproval': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        'PendingAgentInstallation': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        'InstallFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'DriftRepairsFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'DeleteFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'Deleting': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
        'Deleted': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
        'Uninitiated': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    };

    const colorClass = statusColors[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';

    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
            {status}
        </span>
    );
}

// Add Namespace Modal Component
function AddNamespaceModal({
    isOpen,
    onClose,
    onSubmit,
    isPending
}: {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (namespaces: string[]) => void;
    isPending: boolean;
}) {
    const [namespaceInput, setNamespaceInput] = useState('');

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        const namespaces = namespaceInput
            .split(/[,\n]/)
            .map(ns => ns.trim())
            .filter(ns => ns.length > 0);

        if (namespaces.length > 0) {
            onSubmit(namespaces);
        }
    };

    const handleClose = () => {
        setNamespaceInput('');
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Add Namespaces" size="md">
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    <div>
                        <label htmlFor="namespaces" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Namespace Names
                        </label>
                        <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                            Enter namespace names separated by commas or new lines
                        </p>
                        <textarea
                            id="namespaces"
                            rows={4}
                            className="block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                            placeholder="default&#10;production&#10;staging"
                            value={namespaceInput}
                            onChange={(e) => setNamespaceInput(e.target.value)}
                        />
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
                        disabled={isPending || !namespaceInput.trim()}
                        className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isPending ? 'Adding...' : 'Add Namespaces'}
                    </button>
                </div>
            </form>
        </Modal>
    );
}

// Edit Namespace Services Modal Component
function EditNamespaceServicesModal({
    isOpen,
    onClose,
    namespace,
    availableServices,
    onAddServices,
    onRemoveService,
    isAddingServices,
    isRemovingService,
    groups,
}: {
    isOpen: boolean;
    onClose: () => void;
    namespace: ClusterNamespaceServicesData | null;
    availableServices: ClusterServiceDefinitions[];
    onAddServices: (serviceDefinitionIds: string[]) => void;
    onRemoveService: (serviceName: string) => void;
    isAddingServices: boolean;
    isRemovingService: boolean;
    groups: ClusterClusterGroups[];
}) {
    const [selectedServices, setSelectedServices] = useState<Set<string>>(new Set());
    const [searchTerm, setSearchTerm] = useState('');
    const [serviceToRemove, setServiceToRemove] = useState<string | null>(null);

    // Reset selection when modal opens
    useEffect(() => {
        if (isOpen) {
            setSelectedServices(new Set());
            setSearchTerm('');
            setServiceToRemove(null);
        }
    }, [isOpen]);

    if (!namespace) return null;

    const installedServiceNames = namespace.service_names || [];

    // Filter out already installed services
    const uninstalledServices = availableServices.filter(
        s => !installedServiceNames.includes(s.name)
    );

    // Filter by search term
    const filteredServices = uninstalledServices.filter(service => {
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

    const handleAddServices = () => {
        if (selectedServices.size > 0) {
            onAddServices(Array.from(selectedServices));
            setSelectedServices(new Set());
        }
    };

    const handleConfirmRemove = () => {
        if (serviceToRemove) {
            onRemoveService(serviceToRemove);
            setServiceToRemove(null);
        }
    };

    // Helper to get cluster group names for a service
    const getClusterGroupNames = (service: ClusterServiceDefinitions) => {
        return service.cluster_group_ids
            .map(cgId => groups.find(g => g.cluster_group_id === cgId)?.cluster_group_name)
            .filter(Boolean)
            .join(', ') || 'Unknown';
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Edit Services for ${namespace.namespace_name}`} size="lg">
            <div className="space-y-6">
                {/* Currently Installed Services */}
                <div>
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Installed Services ({installedServiceNames.length})
                    </h4>
                    <div className="border border-gray-200 dark:border-gray-700 rounded-md max-h-48 overflow-y-auto">
                        {installedServiceNames.length === 0 ? (
                            <p className="p-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                                No services installed in this namespace
                            </p>
                        ) : (
                            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                                {installedServiceNames.map((serviceName) => {
                                    const serviceInfo = availableServices.find(s => s.name === serviceName);
                                    return (
                                        <li key={serviceName} className="p-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800">
                                            <div>
                                                <span className={`text-sm font-medium ${serviceInfo ? 'text-gray-900 dark:text-gray-100' : 'text-red-600 dark:text-red-400'}`}>
                                                    {serviceName}
                                                    {!serviceInfo && (
                                                        <span className="ml-2 text-xs text-red-500">(not in cluster groups)</span>
                                                    )}
                                                </span>
                                                {serviceInfo && (
                                                    <p className="text-xs text-gray-500 dark:text-gray-400">
                                                        {serviceInfo.org}/{serviceInfo.repo} • {serviceInfo.branch}
                                                    </p>
                                                )}
                                            </div>
                                            <button
                                                onClick={() => setServiceToRemove(serviceName)}
                                                className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                                                title="Remove service"
                                            >
                                                <X className="w-4 h-4" />
                                            </button>
                                        </li>
                                    );
                                })}
                            </ul>
                        )}
                    </div>
                </div>

                {/* Remove Confirmation */}
                {serviceToRemove && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4">
                        <p className="text-sm text-red-800 dark:text-red-200">
                            Are you sure you want to remove <strong>{serviceToRemove}</strong> from this namespace?
                        </p>
                        <div className="mt-3 flex gap-2">
                            <button
                                onClick={handleConfirmRemove}
                                disabled={isRemovingService}
                                className="px-3 py-1.5 text-sm font-medium text-white bg-red-600 rounded hover:bg-red-700 disabled:opacity-50"
                            >
                                {isRemovingService ? 'Removing...' : 'Remove'}
                            </button>
                            <button
                                onClick={() => setServiceToRemove(null)}
                                className="px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-700"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                )}

                {/* Available Services to Add */}
                <div>
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Add Services ({uninstalledServices.length} available)
                    </h4>

                    {/* Search */}
                    <input
                        type="text"
                        placeholder="Search available services..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full px-3 py-2 mb-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />

                    <div className="border border-gray-200 dark:border-gray-700 rounded-md max-h-64 overflow-y-auto">
                        {filteredServices.length === 0 ? (
                            <p className="p-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                                {searchTerm ? 'No services match your search' : 'No more services available to add'}
                            </p>
                        ) : (
                            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                                {filteredServices.map((service) => (
                                    <li key={service.id} className="p-3 hover:bg-gray-50 dark:hover:bg-gray-800">
                                        <label className="flex items-start cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={selectedServices.has(service.id)}
                                                onChange={() => toggleService(service.id)}
                                                className="mt-1 h-4 w-4 text-blue-600 rounded border-gray-300 dark:border-gray-600 dark:bg-gray-800 focus:ring-blue-500"
                                            />
                                            <div className="ml-3 flex-1">
                                                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                                    {service.name}
                                                </span>
                                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                                    {service.org}/{service.repo} • {service.branch}
                                                </p>
                                                <p className="text-xs text-blue-600 dark:text-blue-400">
                                                    From: {getClusterGroupNames(service)}
                                                </p>
                                            </div>
                                        </label>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </div>

                {/* Add Services Button */}
                <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                        {selectedServices.size > 0 && `${selectedServices.size} service(s) selected`}
                    </span>
                    <div className="flex gap-3">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                        >
                            Close
                        </button>
                        <button
                            onClick={handleAddServices}
                            disabled={isAddingServices || selectedServices.size === 0}
                            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {isAddingServices ? 'Adding...' : `Add ${selectedServices.size} Service${selectedServices.size !== 1 ? 's' : ''}`}
                        </button>
                    </div>
                </div>
            </div>
        </Modal>
    );
}

// Generate Manifest Modal Component
function GenerateManifestModal({
    isOpen,
    onClose,
    clusterName,
    onGenerate,
    isPending,
    manifest,
    manifestIsPlaceholder,
    error,
}: {
    isOpen: boolean;
    onClose: () => void;
    clusterName: string;
    onGenerate: (data: { namespace: string; grpcAddress: string; grpcTls: boolean; image: string; regenerateSecret: boolean }) => void;
    isPending: boolean;
    manifest: string | null;
    manifestIsPlaceholder: boolean;
    error?: string | null;
}) {
    const [namespace, setNamespace] = useState('beecd');
    const [grpcAddress, setGrpcAddress] = useState('hive.example.com:443');
    const [grpcTls, setGrpcTls] = useState(true);
    const [image, setImage] = useState('ghcr.io/beecd/agent:latest');
    const [grpcAddressTouched, setGrpcAddressTouched] = useState(false);
    const [grpcTlsTouched, setGrpcTlsTouched] = useState(false);
    const [imageTouched, setImageTouched] = useState(false);
    const [regenerateSecret, setRegenerateSecret] = useState(true);
    const [showRegenerateConfirm, setShowRegenerateConfirm] = useState(false);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        if (!isOpen) return;

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
    }, [isOpen, grpcAddressTouched, grpcTlsTouched, imageTouched]);

    const validateGrpcHostPort = (value: string): string | null => {
        const trimmed = value.trim();
        if (!trimmed) return 'Hive gRPC Address is required.';
        if (trimmed.includes('://')) return 'Do not include a scheme (http:// or https://). Use host:port.';
        if (/[^\S\r\n]/.test(trimmed)) return 'Address must not contain spaces.';
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

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (regenerateSecret) {
            setShowRegenerateConfirm(true);
            return;
        }
        onGenerate({ namespace, grpcAddress, grpcTls, image, regenerateSecret: false });
    };

    const handleConfirmRegenerate = () => {
        setShowRegenerateConfirm(false);
        onGenerate({ namespace, grpcAddress, grpcTls, image, regenerateSecret: true });
    };

    const handleClose = () => {
        setShowRegenerateConfirm(false);
        setCopied(false);
        setGrpcAddressTouched(false);
        setGrpcTlsTouched(false);
        setImageTouched(false);
        setNamespace('beecd');
        setGrpcAddress('hive.example.com:443');
        setGrpcTls(true);
        setImage('ghcr.io/beecd/agent:latest');
        setRegenerateSecret(true);
        onClose();
    };

    const handleCopy = () => {
        if (!manifest) return;
        navigator.clipboard
            .writeText(manifest)
            .then(() => {
                setCopied(true);
                window.setTimeout(() => setCopied(false), 2000);
            })
            .catch(() => {
                // Ignore clipboard errors (permissions, insecure context, etc.)
            });
    };

    return (
        <>
            <Modal isOpen={isOpen} onClose={handleClose} title="Generate Agent Manifest" size="lg">
                {!manifest ? (
                    <form onSubmit={handleSubmit}>
                        <div className="space-y-4">
                            <div>
                                <label htmlFor="namespace" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Agent Namespace
                                </label>
                                <input
                                    type="text"
                                    id="namespace"
                                    className="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                                    value={namespace}
                                    onChange={(e) => setNamespace(e.target.value)}
                                    placeholder="beecd"
                                />
                            </div>
                            <div>
                                <label htmlFor="grpcAddress" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Hive gRPC Address
                                </label>
                                <input
                                    type="text"
                                    id="grpcAddress"
                                    className="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                                    value={grpcAddress}
                                    onChange={(e) => {
                                        setGrpcAddressTouched(true);
                                        setGrpcAddress(e.target.value);
                                    }}
                                    placeholder="hive.example.com:443"
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
                                <label htmlFor="image" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Agent Image
                                </label>
                                <input
                                    type="text"
                                    id="image"
                                    className="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-gray-900 dark:text-gray-100 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                                    value={image}
                                    onChange={(e) => {
                                        setImageTouched(true);
                                        setImage(e.target.value);
                                    }}
                                    placeholder="ghcr.io/beecd/agent:latest"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Agent Secret
                                </label>
                                <div className="mt-2 space-y-2">
                                    <label className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                                        <input
                                            type="radio"
                                            name="regenerateSecret"
                                            checked={regenerateSecret}
                                            onChange={() => setRegenerateSecret(true)}
                                            className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500"
                                        />
                                        <span>
                                            <span className="font-medium">Regenerate secret</span>
                                            <span className="block text-xs text-gray-500 dark:text-gray-400">
                                                Generates a new manifest and invalidates the old credentials.
                                            </span>
                                        </span>
                                    </label>
                                    <label className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                                        <input
                                            type="radio"
                                            name="regenerateSecret"
                                            checked={!regenerateSecret}
                                            onChange={() => setRegenerateSecret(false)}
                                            className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500"
                                        />
                                        <span>
                                            <span className="font-medium">Keep existing secret</span>
                                            <span className="block text-xs text-gray-500 dark:text-gray-400">
                                                Does not change anything. If credentials already exist, the server cannot re-issue the manifest without regenerating.
                                            </span>
                                        </span>
                                    </label>
                                </div>
                            </div>
                        </div>
                        {error && (
                            <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md">
                                <p className="text-sm text-amber-700 dark:text-amber-300">
                                    <strong>Agent credentials already exist.</strong> BeeCD stores only a secure hash of the agent secret, so it cannot re-issue the old manifest.
                                    To get a manifest from here, select "Regenerate secret".
                                </p>
                            </div>
                        )}
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
                                disabled={isPending || !namespace.trim() || !!grpcAddressError || !image.trim()}
                                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {isPending ? 'Generating...' : 'Generate Manifest'}
                            </button>
                        </div>
                    </form>
                ) : (
                    <div className="space-y-4">
                        {manifestIsPlaceholder && (
                            <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-md">
                                <p className="text-sm text-amber-700 dark:text-amber-300">
                                    <strong>Placeholder secret:</strong> this manifest does not include the real agent secret.
                                    Use it only as a template. If you need a working manifest from BeeCD, regenerate the secret.
                                </p>
                            </div>
                        )}
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                    Agent Kubernetes Manifest for {clusterName}
                                </span>
                                <button
                                    onClick={handleCopy}
                                    className="inline-flex items-center px-3 py-1 text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                                >
                                    {copied ? 'Copied' : 'Copy to Clipboard'}
                                </button>
                            </div>
                            <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-xs overflow-x-auto max-h-96">
                                {manifest}
                            </pre>
                        </div>
                        <div className="flex justify-end">
                            <button
                                onClick={handleClose}
                                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
                            >
                                Done
                            </button>
                        </div>
                    </div>
                )}
            </Modal>

            <ConfirmModal
                isOpen={showRegenerateConfirm}
                onClose={() => setShowRegenerateConfirm(false)}
                onConfirm={handleConfirmRegenerate}
                title="Regenerate Agent Secret?"
                message={`This will invalidate the currently deployed agent credentials for "${clusterName}". You must apply the new manifest or the agent will stop connecting.`}
                confirmText="Regenerate & Generate Manifest"
                variant="warning"
                isLoading={isPending}
            />
        </>
    );
}

export function ClusterDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    // State for modals
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [showAddNamespaceModal, setShowAddNamespaceModal] = useState(false);
    const [showManifestModal, setShowManifestModal] = useState(false);
    const [generatedManifest, setGeneratedManifest] = useState<string | null>(null);
    const [generatedManifestIsPlaceholder, setGeneratedManifestIsPlaceholder] = useState(false);
    const [manifestError, setManifestError] = useState<string | null>(null);
    const [editingNamespace, setEditingNamespace] = useState<ClusterNamespaceServicesData | null>(null);

    // Queries
    const { data: cluster, isLoading, isError, error, refetch: refetchCluster } = useCluster(id!);

    // Paginated data - loads all pages for proper search
    const {
        data: namespaces = [],
        isLoading: loadingNamespaces,
        isLoadingMore: loadingMoreNamespaces,
        allLoaded: allNamespacesLoaded,
        refetch: refetchNamespaces
    } = usePaginatedData<ClusterNamespaceServicesData>({
        endpoint: `/clusters/${id}/namespaces`,
        enabled: !!id,
        keyExtractor: (item) => item.namespace_id,
    });

    const {
        data: releases = [],
        isLoading: loadingReleases,
        isLoadingMore: loadingMoreReleases,
        allLoaded: allReleasesLoaded,
        refetch: refetchReleases
    } = usePaginatedData<ReleaseStatus>({
        endpoint: `/clusters/${id}/releases`,
        enabled: !!id,
        keyExtractor: (item) => item.data.id,
    });

    const {
        data: serviceDefinitions = [],
        isLoading: loadingServices,
        isLoadingMore: loadingMoreServices,
        allLoaded: allServicesLoaded,
    } = usePaginatedData<ClusterServiceDefinitions>({
        endpoint: `/clusters/${id}/service-definitions`,
        enabled: !!id,
        keyExtractor: (item) => item.id,
    });

    const { data: errors } = useClusterErrors(id!);
    const { data: heartbeat } = useClusterHeartbeat(id!);
    const { data: groups } = useClusterGroups_ForCluster(id!);

    // Mutations
    const deleteCluster = useDeleteCluster();
    const addNamespaces = useAddClusterNamespaces();
    const initNamespaceServices = useInitNamespaceServices();
    const removeServiceFromNamespace = useRemoveServiceFromNamespace();
    const createCluster = useCreateCluster();

    const handleRefreshAll = () => {
        refetchCluster();
        refetchNamespaces();
        refetchReleases();
    };

    const handleDelete = async () => {
        try {
            await deleteCluster.mutateAsync(id!);
            navigate('/clusters');
        } catch (err) {
            console.error('Failed to delete cluster:', err);
        }
    };

    const handleAddNamespaces = async (namespaceNames: string[]) => {
        try {
            await addNamespaces.mutateAsync({ clusterId: id!, namespaceNames });
            setShowAddNamespaceModal(false);
            refetchNamespaces();
        } catch (err) {
            console.error('Failed to add namespaces:', err);
        }
    };

    const handleAddServicesToNamespace = async (serviceDefinitionIds: string[]) => {
        if (!editingNamespace) return;
        try {
            await initNamespaceServices.mutateAsync({
                namespaceId: editingNamespace.namespace_id,
                serviceDefinitionIds
            });
            setEditingNamespace(null);
            refetchNamespaces();
            refetchReleases();
        } catch (err) {
            console.error('Failed to add services to namespace:', err);
        }
    };

    const handleRemoveServiceFromNamespace = async (serviceName: string) => {
        if (!editingNamespace) return;
        try {
            await removeServiceFromNamespace.mutateAsync({
                namespaceId: editingNamespace.namespace_id,
                serviceName
            });
            // Update the local editingNamespace state to reflect the removal
            setEditingNamespace(prev => {
                if (!prev) return null;
                return {
                    ...prev,
                    service_names: (prev.service_names ?? []).filter(name => name !== serviceName)
                };
            });
            refetchNamespaces();
            refetchReleases();
        } catch (err) {
            console.error('Failed to remove service from namespace:', err);
        }
    };

    const handleGenerateManifest = async (data: { namespace: string; grpcAddress: string; grpcTls: boolean; image: string; regenerateSecret: boolean }) => {
        setManifestError(null);
        try {
            const clusterName = cluster?.name || 'agent';
            const result = await createCluster.mutateAsync({
                name: clusterName,
                context: {
                    agent_name: clusterName,
                    namespace: data.namespace,
                    grpc_address: data.grpcAddress,
                    grpc_tls: data.grpcTls,
                    image: data.image,
                },
                regenerateSecret: data.regenerateSecret,
            });

            if (result.manifest) {
                setGeneratedManifest(result.manifest);
                setGeneratedManifestIsPlaceholder(!!result.manifest_is_placeholder);
            } else if (result.user_existed) {
                setManifestError('Agent credentials already exist for this cluster. Select "Regenerate secret" to generate a new manifest.');
            } else {
                setManifestError('No manifest was generated.');
            }
        } catch (err) {
            console.error('Failed to generate manifest:', err);
            const anyErr = err as unknown as { response?: { data?: unknown; status?: number } };
            const status = anyErr?.response?.status;
            if (status === 409) {
                setManifestError('Agent credentials already exist for this cluster. Select "Regenerate secret" to generate a new manifest.');
            } else if (anyErr?.response?.data) {
                setManifestError(String(anyErr.response.data));
            } else {
                setManifestError('Failed to generate manifest. Please try again.');
            }
        }
    };

    const handleCloseManifestModal = () => {
        setShowManifestModal(false);
        setGeneratedManifest(null);
        setGeneratedManifestIsPlaceholder(false);
        setManifestError(null);
    };


    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                <span className="ml-3 text-gray-600 dark:text-gray-400">Loading cluster...</span>
            </div>
        );
    }

    if (isError) {
        return (
            <div className="p-4">
                <Alert
                    type="error"
                    title="Failed to load cluster"
                    message={error instanceof Error ? error.message : 'Cluster not found'}
                />
                <button
                    onClick={() => navigate('/clusters')}
                    className="mt-4 inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Clusters
                </button>
            </div>
        );
    }

    const namespaceColumns = [
        {
            key: 'namespace_name',
            header: 'Namespace',
            sortable: true,
            getValue: (ns: ClusterNamespaceServicesData) => ns.namespace_name,
            render: (ns: ClusterNamespaceServicesData) => (
                <span className="font-medium dark:text-gray-100">{ns.namespace_name}</span>
            ),
        },
        {
            key: 'service_names',
            header: 'Services',
            render: (ns: ClusterNamespaceServicesData) => (
                <div className="flex flex-wrap gap-1">
                    {ns.service_names?.map((name) => {
                        const serviceInfo = serviceDefinitions.find(s => s.name === name);
                        const isOrphan = !serviceInfo;
                        return (
                            <span
                                key={name}
                                className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${isOrphan
                                    ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                                    }`}
                                title={isOrphan ? 'Service not in cluster groups' : undefined}
                            >
                                {name}
                            </span>
                        );
                    }) || <span className="text-gray-400 dark:text-gray-500">No services</span>}
                </div>
            ),
        },
    ];

    const serviceColumns = [
        {
            key: 'name',
            header: 'Service',
            sortable: true,
            getValue: (s: ClusterServiceDefinitions) => s.name,
            render: (s: ClusterServiceDefinitions) => (
                <Link to={`/services/${s.id}`} className="font-medium text-blue-600 dark:text-blue-400 hover:underline">
                    {s.name}
                </Link>
            ),
        },
        {
            key: 'repo',
            header: 'Repository',
            sortable: true,
            getValue: (s: ClusterServiceDefinitions) => `${s.org}/${s.repo}`,
            render: (s: ClusterServiceDefinitions) => (
                <span className="text-gray-600 dark:text-gray-400">{s.org}/{s.repo}</span>
            ),
        },
        {
            key: 'branch',
            header: 'Branch',
            sortable: true,
            getValue: (s: ClusterServiceDefinitions) => s.branch,
            render: (s: ClusterServiceDefinitions) => (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    {s.branch}
                </span>
            ),
        },
        {
            key: 'cluster_groups',
            header: 'From Cluster Groups',
            render: (s: ClusterServiceDefinitions) => (
                <div className="flex flex-wrap gap-1">
                    {s.cluster_group_ids.map((cgId) => {
                        const group = groups?.find(g => g.cluster_group_id === cgId);
                        return group ? (
                            <Link
                                key={cgId}
                                to={`/cluster-groups/${cgId}`}
                                className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 hover:bg-blue-200 dark:hover:bg-blue-800"
                            >
                                {group.cluster_group_name}
                            </Link>
                        ) : (
                            <span key={cgId} className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                                {cgId}
                            </span>
                        );
                    })}
                </div>
            ),
        },
    ];

    const releaseColumns = [
        {
            key: 'name',
            header: 'Service',
            sortable: true,
            getValue: (r: ReleaseStatus) => r.data.name,
            render: (r: ReleaseStatus) => (
                <Link
                    to={`/releases/${r.data.namespace_id}/${r.data.name}`}
                    className="font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                >
                    {r.data.name}
                </Link>
            ),
        },
        {
            key: 'namespace',
            header: 'Namespace',
            sortable: true,
            getValue: (r: ReleaseStatus) => r.data.namespace,
        },
        {
            key: 'status',
            header: 'Status',
            sortable: true,
            getValue: (r: ReleaseStatus) => r.status,
            render: (r: ReleaseStatus) => <StatusBadge status={r.status} />,
        },
        {
            key: 'version',
            header: 'Version',
            render: (r: ReleaseStatus) => (
                <span className="text-gray-600 dark:text-gray-400 font-mono text-xs">{r.data.version || '-'}</span>
            ),
        },
        {
            key: 'branch',
            header: 'Branch',
            sortable: true,
            getValue: (r: ReleaseStatus) => r.data.branch,
            render: (r: ReleaseStatus) => (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    {r.data.branch}
                </span>
            ),
        },
        {
            key: 'updated_at',
            header: 'Updated',
            sortable: true,
            getValue: (r: ReleaseStatus) => r.data.updated_at,
            render: (r: ReleaseStatus) => (
                <span className="text-gray-500 dark:text-gray-400 text-sm">
                    {r.data.updated_at ? formatRelativeTime(r.data.updated_at) : '-'}
                </span>
            ),
        },
        {
            key: 'actions',
            header: '',
            render: (r: ReleaseStatus) => (
                <div className="flex items-center gap-1">
                    <Link
                        to={`/releases/${r.data.namespace_id}/${r.data.name}`}
                        className="inline-flex items-center p-1.5 text-gray-500 hover:text-blue-600 dark:text-gray-400 dark:hover:text-blue-400"
                        title="View Details"
                    >
                        <Eye className="w-4 h-4" />
                    </Link>
                    {r.data.diff_generation > 0 && (
                        <Link
                            to={`/releases/${r.data.namespace_id}/${r.data.name}`}
                            className="inline-flex items-center p-1.5 text-orange-500 hover:text-orange-600 dark:text-orange-400 dark:hover:text-orange-300"
                            title="View Diff"
                        >
                            <GitCompare className="w-4 h-4" />
                        </Link>
                    )}
                </div>
            ),
        },
    ];

    const errorColumns = [
        {
            key: 'message',
            header: 'Error Message',
            render: (err: HiveError) => (
                <span className="text-red-700 dark:text-red-400">{err.message}</span>
            ),
        },
        {
            key: 'updated_at',
            header: 'Time',
            render: (err: HiveError) => (
                <span className="text-gray-500 dark:text-gray-400 text-sm">{formatRelativeTime(err.updated_at)}</span>
            ),
        },
    ];

    const groupColumns = [
        {
            key: 'name',
            header: 'Group Name',
            render: (g: ClusterClusterGroups) => (
                <Link to={`/cluster-groups/${g.cluster_group_id}`} className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium">
                    {g.cluster_group_name}
                </Link>
            ),
        },
    ];

    return (
        <div className="space-y-6">
            {/* Delete Confirmation Modal */}
            <ConfirmModal
                isOpen={showDeleteModal}
                onClose={() => setShowDeleteModal(false)}
                onConfirm={handleDelete}
                title="Delete Cluster"
                message={`Are you sure you want to delete cluster "${cluster?.name}"? This action cannot be undone and will remove all associated data.`}
                confirmText={deleteCluster.isPending ? 'Deleting...' : 'Delete Cluster'}
                variant="danger"
                isLoading={deleteCluster.isPending}
            />

            {/* Add Namespace Modal */}
            <AddNamespaceModal
                isOpen={showAddNamespaceModal}
                onClose={() => setShowAddNamespaceModal(false)}
                onSubmit={handleAddNamespaces}
                isPending={addNamespaces.isPending}
            />

            {/* Generate Manifest Modal */}
            <GenerateManifestModal
                isOpen={showManifestModal}
                onClose={handleCloseManifestModal}
                clusterName={cluster?.name || ''}
                onGenerate={handleGenerateManifest}
                isPending={createCluster.isPending}
                manifest={generatedManifest}
                manifestIsPlaceholder={generatedManifestIsPlaceholder}
                error={manifestError}
            />

            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate('/clusters')}
                    className="inline-flex items-center text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Clusters
                </button>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setShowManifestModal(true)}
                        className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        <FileCode className="w-4 h-4 mr-2" />
                        Generate Manifest
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
                        disabled={deleteCluster.isPending}
                        className="inline-flex items-center px-3 py-2 border border-red-300 dark:border-red-700 text-sm font-medium rounded-md text-red-700 dark:text-red-400 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50"
                    >
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete
                    </button>
                </div>
            </div>

            <PageHeader
                title={cluster?.name || 'Cluster'}
                description={`Cluster ID: ${id}`}
            />

            {/* Cluster Info Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Server className="w-8 h-8 text-blue-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Agent Version</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{cluster?.version || 'Unknown'}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Layers className="w-8 h-8 text-green-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Kubernetes</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{cluster?.kubernetes_version || 'Unknown'}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Activity className="w-8 h-8 text-purple-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Last Heartbeat</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                                {heartbeat?.last_check_in_at ? formatRelativeTime(heartbeat.last_check_in_at) : 'Never'}
                            </p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <AlertTriangle className={`w-8 h-8 ${(errors?.length ?? 0) > 0 ? 'text-red-500' : 'text-gray-400'}`} />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Errors</p>
                            <p className={`text-lg font-semibold ${(errors?.length ?? 0) > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100'}`}>
                                {errors?.length ?? 0}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Metadata */}
            {cluster?.metadata && (
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Metadata</h3>
                    <pre className="text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-900 p-3 rounded overflow-x-auto">
                        {cluster.metadata}
                    </pre>
                </div>
            )}

            {/* Errors Section */}
            {errors && errors.length > 0 && (
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-red-50 dark:bg-red-900/20">
                        <h3 className="text-lg font-medium text-red-800 dark:text-red-300">
                            <AlertTriangle className="w-5 h-5 inline mr-2" />
                            Agent Errors ({errors.length})
                        </h3>
                    </div>
                    <DataTable
                        data={errors.map((err, i) => ({ ...err, _key: `${err.updated_at}-${i}` }))}
                        columns={errorColumns}
                        keyExtractor={(err) => err._key}
                        searchPlaceholder="Search errors..."
                    />
                </div>
            )}

            {/* Releases Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                            Releases ({releases.length})
                        </h3>
                    </div>
                </div>
                <DataTable
                    data={releases}
                    columns={releaseColumns}
                    keyExtractor={(r) => r.data.id}
                    isLoading={loadingReleases}
                    emptyMessage="No releases found for this cluster"
                    searchPlaceholder="Search releases..."
                    isLoadingMore={loadingMoreReleases}
                    allLoaded={allReleasesLoaded}
                    totalItems={releases.length}
                />
            </div>

            {/* Namespaces Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                        Namespaces ({namespaces.length})
                    </h3>
                </div>
                {namespaces.length === 0 ? (
                    <div className="p-6">
                        <Alert type="info">
                            <p className="font-medium mb-2">No namespaces registered yet</p>
                            <p className="text-sm mb-3">
                                Namespaces are automatically registered when the agent detects them in your cluster.
                            </p>
                            <p className="text-sm font-medium mb-2">To register a namespace:</p>
                            <ol className="text-sm list-decimal list-inside space-y-1 ml-2">
                                <li>Add the label <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono">beecd.io/enabled=true</code> to your namespace</li>
                                <li>The agent will automatically discover and register it on its next sync</li>
                            </ol>
                            <p className="text-sm mt-3 text-gray-600 dark:text-gray-400">
                                Example: <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono">kubectl label namespace my-namespace beecd.io/enabled=true</code>
                            </p>
                        </Alert>
                    </div>
                ) : (
                    <DataTable
                        data={namespaces}
                        columns={namespaceColumns}
                        keyExtractor={(ns) => ns.namespace_id}
                        isLoading={loadingNamespaces}
                        emptyMessage="No namespaces found for this cluster"
                        searchPlaceholder="Search namespaces..."
                        isLoadingMore={loadingMoreNamespaces}
                        allLoaded={allNamespacesLoaded}
                        totalItems={namespaces.length}
                        onRowClick={(ns) => setEditingNamespace(ns)}
                    />
                )}
            </div>

            {/* Cluster Groups */}
            {groups && groups.length > 0 && (
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">Cluster Groups ({groups.length})</h3>
                    </div>
                    <DataTable
                        data={groups}
                        columns={groupColumns}
                        keyExtractor={(g) => g.id}
                    />
                </div>
            )}

            {/* Available Services Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                            <Package className="w-5 h-5 inline mr-2" />
                            Available Services ({serviceDefinitions.length})
                        </h3>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Services available from cluster groups that can be deployed to namespaces
                    </p>
                </div>
                <DataTable
                    data={serviceDefinitions}
                    columns={serviceColumns}
                    keyExtractor={(s) => s.id}
                    isLoading={loadingServices}
                    emptyMessage="No services available from cluster groups"
                    searchPlaceholder="Search services..."
                    isLoadingMore={loadingMoreServices}
                    allLoaded={allServicesLoaded}
                    totalItems={serviceDefinitions.length}
                />
            </div>

            {/* Edit Namespace Services Modal */}
            <EditNamespaceServicesModal
                isOpen={!!editingNamespace}
                onClose={() => setEditingNamespace(null)}
                namespace={editingNamespace}
                availableServices={serviceDefinitions ?? []}
                onAddServices={handleAddServicesToNamespace}
                onRemoveService={handleRemoveServiceFromNamespace}
                isAddingServices={initNamespaceServices.isPending}
                isRemovingService={removeServiceFromNamespace.isPending}
                groups={groups ?? []}
            />
        </div>
    );
}
