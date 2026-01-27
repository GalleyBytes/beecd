import { useState } from 'react';
import { Key, Upload, Trash2 } from 'lucide-react';
import apiClient from '@/lib/api-client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ConfirmModal } from '@/components';

interface Secret {
    purpose: string;
    created_at: string;
}

export function SettingsPage() {
    const queryClient = useQueryClient();
    const [githubToken, setGithubToken] = useState('');
    const [pgpKey, setPgpKey] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [deleteModalOpen, setDeleteModalOpen] = useState(false);
    const [secretToDelete, setSecretToDelete] = useState<string | null>(null);

    const { data: me } = useQuery({
        queryKey: ['auth', 'me'],
        queryFn: async () => {
            const res = await apiClient.get('/auth/me');
            return res.data as { username?: string; tenant_name?: string; tenant_id?: string };
        },
        retry: false,
    });

    const { data: secrets, isLoading } = useQuery<Secret[]>({
        queryKey: ['secrets'],
        queryFn: async () => {
            const res = await apiClient.get<{ secrets: Secret[] }>('/secrets');
            return res.data?.secrets ?? [];
        },
    });

    const createSecretMutation = useMutation({
        mutationFn: async ({ purpose, plaintext }: { purpose: string; plaintext: string }) => {
            await apiClient.post('/secrets', { purpose, plaintext });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['secrets'] });
            setSuccess('Secret saved successfully');
            setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err: any) => {
            const msg =
                err?.response?.data && typeof err.response.data === 'string'
                    ? err.response.data
                    : 'Failed to save secret';
            setError(msg);
            setTimeout(() => setError(null), 5000);
        },
    });

    const deleteSecretMutation = useMutation({
        mutationFn: async (purpose: string) => {
            await apiClient.delete(`/secrets/${purpose}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['secrets'] });
            setSuccess('Secret deleted successfully');
            setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err: any) => {
            const msg =
                err?.response?.data && typeof err.response.data === 'string'
                    ? err.response.data
                    : 'Failed to delete secret';
            setError(msg);
            setTimeout(() => setError(null), 5000);
        },
    });

    const handleSaveGithubToken = () => {
        if (!githubToken.trim()) {
            setError('GitHub token cannot be empty');
            return;
        }
        createSecretMutation.mutate({ purpose: 'github_token', plaintext: githubToken });
        setGithubToken('');
    };

    const handleSavePgpKey = () => {
        if (!pgpKey.trim()) {
            setError('PGP key cannot be empty');
            return;
        }
        createSecretMutation.mutate({ purpose: 'pgp_private_key', plaintext: pgpKey });
        setPgpKey('');
    };

    const handleDelete = (purpose: string) => {
        setSecretToDelete(purpose);
        setDeleteModalOpen(true);
    };

    const confirmDelete = () => {
        if (secretToDelete) {
            deleteSecretMutation.mutate(secretToDelete);
        }
        setDeleteModalOpen(false);
        setSecretToDelete(null);
    };

    const hasGithubToken = secrets?.some((s) => s.purpose === 'github_token');
    const hasPgpKey = secrets?.some((s) => s.purpose === 'pgp_private_key');

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Manage your tenant configuration and secrets
                </p>
            </div>

            {/* Tenant Info */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-5 sm:p-6">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Tenant Information</h2>
                    <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                        <div>
                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Tenant Name</dt>
                            <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                                {me?.tenant_name || 'Unknown'}
                            </dd>
                        </div>
                        <div>
                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Your Email</dt>
                            <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100">
                                {me?.username || 'Unknown'}
                            </dd>
                        </div>
                    </dl>
                </div>
            </div>

            {error && (
                <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4 border border-red-200 dark:border-red-800">
                    <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
                </div>
            )}

            {success && (
                <div className="rounded-md bg-green-50 dark:bg-green-900/20 p-4 border border-green-200 dark:border-green-800">
                    <p className="text-sm text-green-700 dark:text-green-400">{success}</p>
                </div>
            )}

            {/* Secrets Section */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-5 sm:p-6">
                    <div className="flex items-center mb-4">
                        <Key className="h-5 w-5 text-gray-400 dark:text-gray-500 mr-2" />
                        <h2 className="text-lg font-medium text-gray-900 dark:text-white">Secrets</h2>
                    </div>

                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                        Configure tenant-specific secrets for GitHub integration and SOPS encryption.
                        These are stored encrypted and never leave the server.
                    </p>

                    {isLoading && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">Loading secrets...</p>
                    )}

                    {/* GitHub Token */}
                    <div className="mb-6 p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                            <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                GitHub Token
                            </h3>
                            {hasGithubToken && (
                                <button
                                    onClick={() => handleDelete('github_token')}
                                    className="text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                                    title="Delete GitHub token"
                                >
                                    <Trash2 className="h-4 w-4" />
                                </button>
                            )}
                        </div>

                        {hasGithubToken ? (
                            <div className="text-sm text-gray-600 dark:text-gray-400">
                                ✓ Configured (created:{' '}
                                {new Date(
                                    secrets?.find((s) => s.purpose === 'github_token')?.created_at || ''
                                ).toLocaleString()}
                                )
                            </div>
                        ) : (
                            <div>
                                <input
                                    type="password"
                                    value={githubToken}
                                    onChange={(e) => setGithubToken(e.target.value)}
                                    placeholder="ghp_xxxxxxxxxxxx"
                                    className="w-full px-3 py-2 mb-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                />
                                <button
                                    onClick={handleSaveGithubToken}
                                    disabled={!githubToken.trim() || createSecretMutation.isPending}
                                    className="flex items-center px-3 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-md disabled:opacity-50"
                                >
                                    <Upload className="h-4 w-4 mr-2" />
                                    Save
                                </button>
                            </div>
                        )}
                    </div>

                    {/* PGP Key */}
                    <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                            <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                PGP Private Key (SOPS)
                            </h3>
                            {hasPgpKey && (
                                <button
                                    onClick={() => handleDelete('pgp_private_key')}
                                    className="text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                                    title="Delete PGP key"
                                >
                                    <Trash2 className="h-4 w-4" />
                                </button>
                            )}
                        </div>

                        {hasPgpKey ? (
                            <div className="text-sm text-gray-600 dark:text-gray-400">
                                ✓ Configured (created:{' '}
                                {new Date(
                                    secrets?.find((s) => s.purpose === 'pgp_private_key')?.created_at || ''
                                ).toLocaleString()}
                                )
                            </div>
                        ) : (
                            <div>
                                <textarea
                                    value={pgpKey}
                                    onChange={(e) => setPgpKey(e.target.value)}
                                    placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                                    rows={6}
                                    className="w-full px-3 py-2 mb-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500 font-mono text-xs"
                                />
                                <button
                                    onClick={handleSavePgpKey}
                                    disabled={!pgpKey.trim() || createSecretMutation.isPending}
                                    className="flex items-center px-3 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-md disabled:opacity-50"
                                >
                                    <Upload className="h-4 w-4 mr-2" />
                                    Save
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Delete Confirmation Modal */}
            <ConfirmModal
                isOpen={deleteModalOpen}
                onClose={() => {
                    setDeleteModalOpen(false);
                    setSecretToDelete(null);
                }}
                onConfirm={confirmDelete}
                title="Delete Secret"
                message={`Are you sure you want to delete the secret "${secretToDelete}"? This action cannot be undone.`}
                confirmText="Delete"
                cancelText="Cancel"
                variant="danger"
                isLoading={deleteSecretMutation.isPending}
            />
        </div>
    );
}
