import { useState, type FormEvent, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '@/lib/api-client';
import { ThemeToggle } from '@/components';
import { useCurrentTenant, useTenantUrl, useConfig } from '@/contexts/ConfigContext';

export function LoginPage() {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const { loading: configLoading } = useConfig();
    const tenantSlug = useCurrentTenant();
    const getTenantUrl = useTenantUrl();
    const isBaseDomain = tenantSlug === null;

    // Derive step from isBaseDomain - recalculates when config loads
    const step = useMemo(() => isBaseDomain ? 'tenant' : 'credentials', [isBaseDomain]);
    const [tenantName, setTenantName] = useState('');

    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            // Base domain two-step flow: redirect to tenant subdomain
            if (isBaseDomain && step === 'tenant') {
                const slug = tenantName.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
                if (!slug) {
                    setError('Please enter a valid tenant name');
                    setLoading(false);
                    return;
                }
                // Redirect to tenant subdomain using configured base domain
                window.location.href = getTenantUrl(slug, '/login');
                return;
            }

            // Actual login (either from tenant subdomain or after redirect)
            await apiClient.post('/auth/login', {
                username: username.trim(),
                password,
            });
            navigate('/');
        } catch (err: any) {
            const msg =
                err?.response?.data && typeof err.response.data === 'string'
                    ? err.response.data
                    : 'Login failed';
            setError(msg);
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    // Show loading while config is being fetched
    if (configLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
                <div className="text-gray-600 dark:text-gray-400">Loading...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
            {/* Theme toggle in top right */}
            <div className="absolute top-4 right-4">
                <ThemeToggle />
            </div>

            <div className="max-w-md w-full space-y-8">
                <div>
                    <h1 className="text-center text-4xl font-bold text-gray-900 dark:text-white">🐝 BeeCD</h1>
                    <h2 className="mt-6 text-center text-2xl font-bold text-gray-900 dark:text-white">
                        Sign in to HiveHQ
                    </h2>
                </div>

                {error && (
                    <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4 border border-red-200 dark:border-red-800">
                        <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
                    </div>
                )}

                <div className="space-y-6">
                    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow dark:shadow-gray-900">
                        {isBaseDomain && step === 'tenant' ? (
                            // Step 1: Ask for tenant name at base domain
                            <>
                                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                                    Enter your tenant
                                </h3>
                                <form onSubmit={handleSubmit} className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                            Tenant Name
                                        </label>
                                        <input
                                            type="text"
                                            value={tenantName}
                                            onChange={(e) => setTenantName(e.target.value)}
                                            placeholder="your-company"
                                            autoFocus
                                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                        />
                                    </div>
                                    <button
                                        type="submit"
                                        disabled={loading || !tenantName.trim()}
                                        className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-800 disabled:opacity-50"
                                    >
                                        {loading ? 'Working...' : 'Continue'}
                                    </button>
                                </form>
                                <div className="mt-4 text-center">
                                    <button
                                        type="button"
                                        onClick={() => navigate('/register')}
                                        className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                    >
                                        Don't have a tenant? Register here
                                    </button>
                                </div>
                            </>
                        ) : (
                            // Step 2: Username/password (either on tenant subdomain or after redirect)
                            <>
                                <div className="mb-4">
                                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                        Sign in
                                    </h3>
                                </div>

                                <form onSubmit={handleSubmit} className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                            Username
                                        </label>
                                        <input
                                            type="text"
                                            value={username}
                                            onChange={(e) => setUsername(e.target.value)}
                                            autoComplete="username"
                                            autoFocus
                                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                            Password
                                        </label>
                                        <input
                                            type="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            autoComplete="current-password"
                                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={loading || !username.trim() || !password.trim()}
                                        className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-800 disabled:opacity-50"
                                    >
                                        {loading ? 'Working...' : 'Sign In'}
                                    </button>
                                </form>

                                {!isBaseDomain && (
                                    <div className="mt-4 text-center">
                                        <button
                                            type="button"
                                            onClick={() => {
                                                const protocol = window.location.protocol;
                                                const baseDomain = window.location.hostname.split('.').slice(1).join('.');
                                                const port = window.location.port ? `:${window.location.port}` : '';
                                                window.location.href = `${protocol}//${baseDomain}${port}/login`;
                                            }}
                                            className="text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300 underline"
                                        >
                                            Change tenant
                                        </button>
                                    </div>
                                )}

                                {isBaseDomain && (
                                    <div className="mt-4 text-center">
                                        <button
                                            type="button"
                                            onClick={() => navigate('/register')}
                                            className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                        >
                                            Don't have a tenant? Register here
                                        </button>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
