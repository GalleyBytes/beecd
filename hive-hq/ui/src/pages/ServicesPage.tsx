import { Link } from 'react-router-dom';
import { RefreshCw, Package, GitBranch } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { usePaginatedData } from '@/hooks';
import type { ServiceDefinitionData } from '@/types';

export function ServicesPage() {
    const { data, isLoading, isLoadingMore, allLoaded, error, refetch } = usePaginatedData<ServiceDefinitionData>({
        endpoint: '/service-definitions',
        keyExtractor: (item) => item.service_definition_id,
    });
    const isError = !!error;
    const isFetching = isLoading || isLoadingMore;

    const columns = [
        {
            key: 'name',
            header: 'Service',
            sortable: true,
            getValue: (service: ServiceDefinitionData) => service.name,
            render: (service: ServiceDefinitionData) => (
                <div className="flex items-center">
                    <Package className="w-4 h-4 mr-2 text-purple-500 dark:text-purple-400" />
                    <Link
                        to={`/services/name/${service.name}`}
                        onClick={(e) => e.stopPropagation()}
                        className="font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                        title="View all definitions for this service"
                    >
                        {service.name}
                    </Link>
                </div>
            ),
        },
        {
            key: 'definition',
            header: 'Definition',
            sortable: true,
            getValue: (service: ServiceDefinitionData) => `${service.org}/${service.repo}@${service.branch}`,
            render: (service: ServiceDefinitionData) => (
                <Link
                    to={`/services/${service.service_definition_id}`}
                    onClick={(e) => e.stopPropagation()}
                    className="text-gray-700 hover:text-blue-600 dark:text-gray-300 dark:hover:text-blue-400"
                    title="View this specific definition"
                >
                    <span className="text-gray-500 dark:text-gray-400">{service.org}/{service.repo}</span>
                    <span className="mx-1 text-gray-400">@</span>
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                        <GitBranch className="w-3 h-3 mr-1" />
                        {service.branch}
                    </span>
                </Link>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Services"
                description="Service definitions for GitOps deployments"
                actions={
                    <button
                        onClick={() => refetch()}
                        disabled={isFetching}
                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                    >
                        <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
                        Refresh
                    </button>
                }
            />

            {isError && (
                <div className="mb-4">
                    <Alert
                        type="error"
                        title="Failed to load services"
                        message={error instanceof Error ? error.message : 'An unknown error occurred'}
                    />
                </div>
            )}

            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <DataTable
                    data={data}
                    columns={columns}
                    keyExtractor={(service) => service.service_definition_id}
                    isLoading={isLoading}
                    isLoadingMore={isLoadingMore}
                    allLoaded={allLoaded}
                    emptyMessage="No services found. Create a service definition to get started."
                    searchPlaceholder="Search services..."
                />
            </div>
        </div>
    );
}
