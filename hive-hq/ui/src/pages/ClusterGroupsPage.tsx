import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Plus, X } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { usePaginatedData, useCreateClusterGroup } from '@/hooks';
import type { ClusterGroupData } from '@/types';

export function ClusterGroupsPage() {
    const navigate = useNavigate();
    const [showAddModal, setShowAddModal] = useState(false);
    const [newGroupName, setNewGroupName] = useState('');

    const { data, isLoading, isLoadingMore, allLoaded, error, refetch } = usePaginatedData<ClusterGroupData>({
        endpoint: '/cluster-groups',
        keyExtractor: (item) => item.id,
    });
    const isError = !!error;
    const isFetching = isLoading || isLoadingMore;

    const createGroupMutation = useCreateClusterGroup();

    const handleAddGroup = async () => {
        if (!newGroupName.trim()) return;

        try {
            await createGroupMutation.mutateAsync({ name: newGroupName.trim() });
            setShowAddModal(false);
            setNewGroupName('');
            refetch();
        } catch (err) {
            console.error('Failed to create cluster group:', err);
        }
    };

    const columns = [
        {
            key: 'name',
            header: 'Group Name',
            sortable: true,
            getValue: (group: ClusterGroupData) => group.name,
            render: (group: ClusterGroupData) => (
                <span className="font-medium text-blue-600 dark:text-blue-400">{group.name}</span>
            ),
        },
        {
            key: 'priority',
            header: 'Priority',
            sortable: true,
            getValue: (group: ClusterGroupData) => group.priority,
            render: (group: ClusterGroupData) => (
                <span className="text-gray-600 dark:text-gray-400">{group.priority}</span>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Cluster Groups"
                description="Organize clusters into groups for batch deployments"
                actions={
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => refetch()}
                            disabled={isFetching}
                            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                        >
                            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
                            Refresh
                        </button>
                        <button
                            onClick={() => setShowAddModal(true)}
                            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        >
                            <Plus className="w-4 h-4 mr-2" />
                            Add Group
                        </button>
                    </div>
                }
            />

            {isError && (
                <div className="mb-4">
                    <Alert
                        type="error"
                        title="Failed to load cluster groups"
                        message={error instanceof Error ? error.message : 'An unknown error occurred'}
                    />
                </div>
            )}

            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <DataTable
                    data={data}
                    columns={columns}
                    keyExtractor={(group) => group.id}
                    isLoading={isLoading}
                    isLoadingMore={isLoadingMore}
                    allLoaded={allLoaded}
                    emptyMessage="No cluster groups found. Create a group to organize your clusters."
                    searchPlaceholder="Search cluster groups..."
                    onRowClick={(group) => navigate(`/cluster-groups/${group.id}`)}
                />
            </div>

            {/* Add Cluster Group Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => setShowAddModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                    Create Cluster Group
                                </h3>
                                <button
                                    onClick={() => setShowAddModal(false)}
                                    className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>

                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                Create a new cluster group to organize your clusters for deployments.
                            </p>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    Group Name
                                </label>
                                <input
                                    type="text"
                                    value={newGroupName}
                                    onChange={(e) => setNewGroupName(e.target.value)}
                                    placeholder="e.g., production, staging"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500"
                                    onKeyDown={(e) => e.key === 'Enter' && handleAddGroup()}
                                />
                            </div>

                            {createGroupMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to create cluster group
                                    </p>
                                </div>
                            )}

                            <div className="mt-6 flex justify-end gap-3">
                                <button
                                    onClick={() => setShowAddModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleAddGroup}
                                    disabled={!newGroupName.trim() || createGroupMutation.isPending}
                                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md"
                                >
                                    {createGroupMutation.isPending ? 'Creating...' : 'Create Group'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
