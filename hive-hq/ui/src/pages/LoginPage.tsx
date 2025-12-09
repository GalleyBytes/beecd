import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '@/lib/api-client';
import { ThemeToggle } from '@/components';

export function LoginPage() {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [mode, setMode] = useState<'login' | 'bootstrap'>('login');
    const [bootstrapAvailable, setBootstrapAvailable] = useState<boolean>(false);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                const res = await apiClient.get('/auth/bootstrap/status');
                const required = !!res.data?.bootstrap_required;
                if (!cancelled) {
                    setBootstrapAvailable(required);
                    if (!required && mode === 'bootstrap') {
                        setMode('login');
                    }
                }
            } catch {
                // If status check fails, default to hiding bootstrap. It's safer.
                if (!cancelled) {
                    setBootstrapAvailable(false);
                    if (mode === 'bootstrap') {
                        setMode('login');
                    }
                }
            }
        })();

        return () => {
            cancelled = true;
        };
        // mode is intentionally included so we can force-switch back to login if needed.
    }, [mode]);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            const path = mode === 'bootstrap' ? '/auth/bootstrap' : '/auth/login';
            await apiClient.post(path, {
                username: username.trim(),
                password,
            });
            navigate('/');
        } catch (err: any) {
            if (mode === 'bootstrap' && err?.response?.status === 409) {
                setBootstrapAvailable(false);
                setMode('login');
            }
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
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                {mode === 'bootstrap' ? 'Initial Setup' : 'Sign in'}
                            </h3>
                            {bootstrapAvailable && (
                                <button
                                    type="button"
                                    onClick={() => setMode(mode === 'login' ? 'bootstrap' : 'login')}
                                    className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                >
                                    {mode === 'login' ? 'Create first user' : 'Back to login'}
                                </button>
                            )}
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
                                    autoComplete={mode === 'bootstrap' ? 'new-password' : 'current-password'}
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                />
                            </div>

                            <button
                                type="submit"
                                disabled={loading || !username.trim() || !password.trim()}
                                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-800 disabled:opacity-50"
                            >
                                {loading
                                    ? 'Working...'
                                    : mode === 'bootstrap'
                                        ? 'Create User'
                                        : 'Sign In'}
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}
