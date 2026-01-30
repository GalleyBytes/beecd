import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '@/lib/api-client';
import { ThemeToggle } from '@/components';
import { useTenantUrl, useConfig } from '@/contexts/ConfigContext';

export function RegisterPage() {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const { loading: configLoading } = useConfig();
    const getTenantUrl = useTenantUrl();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [tenantName, setTenantName] = useState('');

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setSuccess(null);

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            setLoading(false);
            return;
        }

        if (!email.includes('@')) {
            setError('Username must be a valid email address');
            setLoading(false);
            return;
        }

        try {
            const res = await apiClient.post('/api/tenants/register', {
                username: email.trim(),
                password,
                tenant_name: tenantName.trim(),
            });

            const domain = res.data?.domain;
            if (domain) {
                // Extract slug from domain (the domain from API is just the slug)
                const slug = domain.split('.')[0];
                setSuccess(`Tenant created! Redirecting...`);

                // Redirect to tenant subdomain after brief delay using configured base domain
                setTimeout(() => {
                    window.location.href = getTenantUrl(slug, '/');
                }, 2000);
            } else {
                navigate('/login');
            }
        } catch (err: any) {
            const msg =
                err?.response?.data && typeof err.response.data === 'string'
                    ? err.response.data
                    : 'Registration failed';
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
            <div className="absolute top-4 right-4">
                <ThemeToggle />
            </div>

            <div className="max-w-md w-full space-y-8">
                <div>
                    <h1 className="text-center text-4xl font-bold text-gray-900 dark:text-white">🐝 BeeCD</h1>
                    <h2 className="mt-6 text-center text-2xl font-bold text-gray-900 dark:text-white">
                        Create Your Tenant
                    </h2>
                    <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                        Register your organization on BeeCD
                    </p>
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

                <div className="space-y-6">
                    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow dark:shadow-gray-900">
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    Tenant Name
                                </label>
                                <input
                                    type="text"
                                    value={tenantName}
                                    onChange={(e) => setTenantName(e.target.value)}
                                    placeholder="e.g., Acme Inc"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                />
                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                    Your organization's name
                                </p>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    Email
                                </label>
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="admin@example.com"
                                    autoComplete="email"
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
                                    autoComplete="new-password"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                    Confirm Password
                                </label>
                                <input
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    autoComplete="new-password"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                />
                            </div>

                            <button
                                type="submit"
                                disabled={loading || !email.trim() || !password.trim() || !tenantName.trim()}
                                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-800 disabled:opacity-50"
                            >
                                {loading ? 'Creating...' : 'Create Tenant'}
                            </button>
                        </form>

                        <div className="mt-4 text-center">
                            <button
                                type="button"
                                onClick={() => navigate('/login')}
                                className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                            >
                                Already have a tenant? Sign in
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
