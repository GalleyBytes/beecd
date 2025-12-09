import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Package, Settings, Trash2 } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { useServiceByName, useDeleteService } from '@/hooks';
import type { ServiceDefinitionData } from '@/types';

export function ServiceNamePage() {
    const { name } = useParams<{ name: string }>();
    const navigate = useNavigate();

    const [showDeleteModal, setShowDeleteModal] = useState(false);

    const { data: services = [], isLoading, isError, error, refetch } = useServiceByName(name!);
    const deleteMutation = useDeleteService();

    const handleDelete = async () => {
        if (!name) return;

        try {
            await deleteMutation.mutateAsync(name);
            navigate('/services');
        } catch (err) {
            console.error('Failed to delete service:', err);
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
                <span className="ml-3 text-gray-600 dark:text-gray-400">Loading service...</span>
            </div>
        );
    }

    if (isError) {
        return (
            <div className="p-4">
                <Alert
                    type="error"
                    title="Failed to load service"
                    message={error instanceof Error ? error.message : 'Service not found'}
                />
                <button
                    onClick={() => navigate('/services')}
                    className="mt-4 inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Services
                </button>
            </div>
        );
    }

    const buildTargetColumns = [
        {
            key: 'target',
            header: 'Repository & Branch',
            sortable: true,
            getValue: (s: ServiceDefinitionData) => `${s.org}/${s.repo}@${s.branch}`,
            render: (s: ServiceDefinitionData) => (
                <div className="flex items-center">
                    <Link
                        to={`/services/${s.service_definition_id}`}
                        className="font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                    >
                        <span>{s.org}/{s.repo}@</span>
                        <span className="font-bold">{s.branch}</span>
                    </Link>
                </div>
            ),
        },
        {
            key: 'source_requirements',
            header: 'Source Requirements',
            getValue: (s: ServiceDefinitionData) => s.source_branch_requirements || '',
            render: (s: ServiceDefinitionData) => (
                <span className="text-gray-600 dark:text-gray-400">
                    {s.source_branch_requirements || '-'}
                </span>
            ),
        },
    ];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate('/services')}
                    className="inline-flex items-center text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Services
                </button>
                <button
                    onClick={() => refetch()}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                </button>
            </div>

            <PageHeader
                title={name || 'Service'}
                description="Service configuration and build targets"
            />

            {/* Service Definitions Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                                <Package className="w-5 h-5 mr-2 text-purple-500" />
                                Service Definitions
                            </h3>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                                A service can have multiple definitions across different repositories and branches
                            </p>
                        </div>
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                            {services.length} {services.length === 1 ? 'definition' : 'definitions'}
                        </span>
                    </div>
                </div>
                <DataTable
                    data={services}
                    columns={buildTargetColumns}
                    keyExtractor={(s) => s.service_definition_id}
                    isLoading={isLoading}
                    emptyMessage="No service definitions found"
                    searchPlaceholder="Search definitions..."
                    onRowClick={(s) => navigate(`/services/${s.service_definition_id}`)}
                />
            </div>

            {/* Settings Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden max-w-2xl">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                        <Settings className="w-5 h-5 mr-2 text-gray-500" />
                        Settings
                    </h3>
                </div>
                <div className="p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <dt className="text-sm font-medium text-gray-900 dark:text-white">Delete Service</dt>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                Deletes service and all service relationships
                            </p>
                        </div>
                        <button
                            onClick={() => setShowDeleteModal(true)}
                            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700"
                        >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Delete
                        </button>
                    </div>
                </div>
            </div>

            {/* Delete Confirmation Modal */}
            {showDeleteModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => setShowDeleteModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                                Delete Service
                            </h3>
                            <p className="text-gray-600 dark:text-gray-400 mb-2">
                                Are you sure you want to delete service:
                            </p>
                            <p className="text-center font-bold text-gray-900 dark:text-white my-4 text-lg">
                                {name}
                            </p>

                            {deleteMutation.isError && (
                                <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to delete service
                                    </p>
                                </div>
                            )}

                            <div className="flex justify-end gap-3">
                                <button
                                    onClick={() => setShowDeleteModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleDelete}
                                    disabled={deleteMutation.isPending}
                                    className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
