import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, ExternalLink, Plus, X } from 'lucide-react';
import { PageHeader, DataTable, Alert } from '@/components';
import { usePaginatedData, useCreateRepo } from '@/hooks';
import type { RepoData } from '@/types';

const GITHUB_URL = 'https://github.com';

function inferHost(input: string): string | null {
    const trimmed = input.trim();
    if (!trimmed) return null;

    try {
        if (trimmed.includes('://')) {
            return new URL(trimmed).hostname.replace(/^www\./, '').toLowerCase();
        }

        if (trimmed.startsWith('git@')) {
            // git@host:org/repo(.git)
            const afterAt = trimmed.slice(4);
            const hostPart = afterAt.split(/[:/]/)[0];
            return hostPart.replace(/^www\./, '').toLowerCase();
        }

        // host/org/repo (no scheme)
        const parts = trimmed.split('/');
        if (parts.length >= 3 && parts[0].includes('.')) {
            return parts[0].replace(/^www\./, '').toLowerCase();
        }

        // shorthand org/repo -> github.com
        if (parts.length === 2) {
            return 'github.com';
        }
    } catch {
        // ignore
    }

    return null;
}

export function ReposPage() {
    const navigate = useNavigate();
    const [showAddModal, setShowAddModal] = useState(false);
    const [newUrl, setNewUrl] = useState('');
    const [selectedProvider, setSelectedProvider] = useState('');

    const { data, isLoading, isLoadingMore, allLoaded, error, refetch } = usePaginatedData<RepoData>({
        endpoint: '/repos',
        keyExtractor: (repo) => repo.id,
    });
    const isError = !!error;
    const isFetching = isLoading || isLoadingMore;

    const createRepoMutation = useCreateRepo();

    const host = inferHost(newUrl);
    const needsProvider = !!host && host !== 'github.com';

    const handleAddRepo = async () => {
        if (!newUrl.trim()) return;
        if (needsProvider && !selectedProvider) return;

        try {
            const result = await createRepoMutation.mutateAsync({
                url: newUrl.trim(),
                provider: needsProvider ? selectedProvider : undefined,
            });
            setShowAddModal(false);
            setNewUrl('');
            setSelectedProvider('');
            refetch();
            // Navigate to the new repo
            if (result?.id) {
                navigate(`/repos/${result.id}`);
            }
        } catch (err) {
            console.error('Failed to add repository:', err);
        }
    };

    const columns = [
        {
            key: 'org',
            header: 'Organization',
            sortable: true,
            getValue: (repo: RepoData) => repo.org,
            render: (repo: RepoData) => (
                <span className="font-medium dark:text-gray-100">{repo.org}</span>
            ),
        },
        {
            key: 'repo',
            header: 'Repository',
            sortable: true,
            getValue: (repo: RepoData) => repo.repo,
            render: (repo: RepoData) => (
                <div className="flex items-center">
                    <span className="font-medium text-blue-600 dark:text-blue-400">{repo.repo}</span>
                    <a
                        href={`${((repo as any).web_base_url ?? GITHUB_URL)}/${repo.org}/${repo.repo}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="ml-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                        <ExternalLink className="w-4 h-4" />
                    </a>
                </div>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Repositories"
                description="Git repositories configured for deployments"
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
                            Add Repository
                        </button>
                    </div>
                }
            />

            {isError && (
                <div className="mb-4">
                    <Alert
                        type="error"
                        title="Failed to load repositories"
                        message={error instanceof Error ? error.message : 'An unknown error occurred'}
                    />
                </div>
            )}

            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <DataTable
                    data={data}
                    columns={columns}
                    keyExtractor={(repo) => repo.id}
                    isLoading={isLoading}
                    isLoadingMore={isLoadingMore}
                    allLoaded={allLoaded}
                    emptyMessage="No repositories found. Add a repository to get started."
                    onRowClick={(repo) => navigate(`/repos/${repo.id}`)}
                    searchPlaceholder="Search repositories..."
                />
            </div>

            {/* Add Repository Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => setShowAddModal(false)} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                    Add Repository
                                </h3>
                                <button
                                    onClick={() => setShowAddModal(false)}
                                    className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>

                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                {needsProvider
                                    ? 'Select the provider type for this host.'
                                    : 'Add a GitHub repository to track for deployments.'}
                            </p>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        {needsProvider ? 'Repository URL' : 'GitHub Repository URL'}
                                    </label>
                                    <input
                                        type="text"
                                        value={newUrl}
                                        onChange={(e) => {
                                            setNewUrl(e.target.value);
                                            setSelectedProvider('');
                                        }}
                                        placeholder="e.g., https://github.com/galleybytes/beecd"
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500"
                                    />
                                </div>

                                {needsProvider && (
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                            Provider (required for {host})
                                        </label>
                                        <select
                                            value={selectedProvider}
                                            onChange={(e) => setSelectedProvider(e.target.value)}
                                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-blue-500 focus:border-blue-500"
                                        >
                                            <option value="">Select provider...</option>
                                            <option value="github">GitHub (GitHub Enterprise)</option>
                                            <option value="forgejo">Forgejo / Codeberg (not yet supported)</option>
                                            <option value="gitlab">GitLab (not yet supported)</option>
                                        </select>
                                    </div>
                                )}
                            </div>

                            {createRepoMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        {((createRepoMutation.error as any)?.response?.data as string) ||
                                            (createRepoMutation.error as any)?.message ||
                                            'Failed to add repository'}
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
                                    onClick={handleAddRepo}
                                    disabled={
                                        !newUrl.trim() ||
                                        createRepoMutation.isPending ||
                                        (needsProvider && !selectedProvider)
                                    }
                                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md"
                                >
                                    {createRepoMutation.isPending ? 'Adding...' : 'Add Repository'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
