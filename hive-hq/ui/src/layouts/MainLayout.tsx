import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
    Server,
    GitBranch,
    Layers,
    FolderGit2,
    Home,
    Menu,
    X,
    User,
    LogOut
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { ThemeToggle } from '@/components';
import apiClient from '@/lib/api-client';
import { useQuery, useQueryClient } from '@tanstack/react-query';

const navigation = [
    { name: 'Home', href: '/', icon: Home },
    { name: 'Clusters', href: '/clusters', icon: Server },
    { name: 'Services', href: '/services', icon: Layers },
    { name: 'Repositories', href: '/repos', icon: FolderGit2 },
    { name: 'Cluster Groups', href: '/cluster-groups', icon: GitBranch },
];

export function MainLayout() {
    const location = useLocation();
    const navigate = useNavigate();
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [userMenuOpen, setUserMenuOpen] = useState(false);
    const [userMenuPinned, setUserMenuPinned] = useState(false);
    const userMenuRef = useRef<HTMLDivElement | null>(null);
    const userMenuDropdownRef = useRef<HTMLDivElement | null>(null);
    const queryClient = useQueryClient();

    const { data: me } = useQuery({
        queryKey: ['auth', 'me'],
        queryFn: async () => {
            const res = await apiClient.get('/auth/me');
            return res.data as { username?: string };
        },
        retry: false,
    });

    const handleLogout = async () => {
        try {
            await apiClient.post('/auth/logout');
        } finally {
            queryClient.clear();
            navigate('/login', { replace: true });
        }
    };

    useEffect(() => {
        if (!userMenuOpen) return;

        const onPointerDown = (e: PointerEvent) => {
            const el = userMenuRef.current;
            if (!el) return;
            if (e.target instanceof Node && el.contains(e.target)) return;
            setUserMenuOpen(false);
            setUserMenuPinned(false);
        };

        const onKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                setUserMenuOpen(false);
                setUserMenuPinned(false);
            }
        };

        document.addEventListener('pointerdown', onPointerDown);
        document.addEventListener('keydown', onKeyDown);
        return () => {
            document.removeEventListener('pointerdown', onPointerDown);
            document.removeEventListener('keydown', onKeyDown);
        };
    }, [userMenuOpen]);

    useEffect(() => {
        if (!userMenuOpen) return;
        if (userMenuPinned) return;

        const onPointerMove = (e: PointerEvent) => {
            if (e.pointerType !== 'mouse') return;
            const root = userMenuRef.current;
            if (!root) return;

            // The dropdown is absolutely positioned, so it does not affect the root
            // element's bounding box. Compute a union box of trigger + dropdown.
            const triggerRect = root.getBoundingClientRect();
            const dropdownRect = userMenuDropdownRef.current
                ? userMenuDropdownRef.current.getBoundingClientRect()
                : null;

            const left = dropdownRect ? Math.min(triggerRect.left, dropdownRect.left) : triggerRect.left;
            const top = dropdownRect ? Math.min(triggerRect.top, dropdownRect.top) : triggerRect.top;
            const right = dropdownRect ? Math.max(triggerRect.right, dropdownRect.right) : triggerRect.right;
            const bottom = dropdownRect ? Math.max(triggerRect.bottom, dropdownRect.bottom) : triggerRect.bottom;

            const width = Math.max(1, right - left);
            const height = Math.max(1, bottom - top);
            const slackX = Math.min(60, Math.max(12, width * 0.15));
            const slackY = Math.min(60, Math.max(12, height * 0.15));

            const inside =
                e.clientX >= left - slackX &&
                e.clientX <= right + slackX &&
                e.clientY >= top - slackY &&
                e.clientY <= bottom + slackY;

            if (!inside) setUserMenuOpen(false);
        };

        document.addEventListener('pointermove', onPointerMove);
        return () => document.removeEventListener('pointermove', onPointerMove);
    }, [userMenuOpen, userMenuPinned]);

    return (
        <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
            {/* Mobile sidebar backdrop */}
            {sidebarOpen && (
                <div
                    className="fixed inset-0 z-40 bg-gray-600 bg-opacity-75 lg:hidden"
                    onClick={() => setSidebarOpen(false)}
                />
            )}

            {/* Mobile sidebar */}
            <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 dark:bg-gray-950 transform transition-transform duration-300 ease-in-out lg:hidden ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <div className="flex items-center justify-between h-16 px-4 bg-gray-800 dark:bg-gray-900">
                    <span className="text-xl font-bold text-white">BeeCD</span>
                    <button
                        onClick={() => setSidebarOpen(false)}
                        className="text-gray-400 hover:text-white"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>
                <nav className="mt-5 px-2 space-y-1">
                    {navigation.map((item) => {
                        const isActive = location.pathname === item.href;
                        return (
                            <Link
                                key={item.name}
                                to={item.href}
                                onClick={() => setSidebarOpen(false)}
                                className={`group flex items-center px-2 py-2 text-base font-medium rounded-md ${isActive
                                    ? 'bg-gray-800 text-white'
                                    : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                                    }`}
                            >
                                <item.icon className="mr-4 h-6 w-6 flex-shrink-0" />
                                {item.name}
                            </Link>
                        );
                    })}
                </nav>
            </div>

            {/* Desktop sidebar */}
            <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
                <div className="flex flex-col flex-grow bg-gray-900 dark:bg-gray-950 overflow-y-auto">
                    <div className="flex items-center h-16 px-4 bg-gray-800 dark:bg-gray-900">
                        <span className="text-xl font-bold text-white">🐝 BeeCD</span>
                    </div>
                    <nav className="mt-5 flex-1 px-2 space-y-1">
                        {navigation.map((item) => {
                            const isActive = location.pathname === item.href ||
                                (item.href !== '/' && location.pathname.startsWith(item.href));
                            return (
                                <Link
                                    key={item.name}
                                    to={item.href}
                                    className={`group flex items-center px-2 py-2 text-sm font-medium rounded-md ${isActive
                                        ? 'bg-gray-800 text-white'
                                        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                                        }`}
                                >
                                    <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                                    {item.name}
                                </Link>
                            );
                        })}
                    </nav>
                    <div className="flex-shrink-0 border-t border-gray-800 p-4">
                        <ThemeToggle />
                    </div>
                </div>
            </div>

            {/* Main content */}
            <div className="lg:pl-64 flex flex-col flex-1">
                {/* Top bar */}
                <div className="sticky top-0 z-10 flex h-16 flex-shrink-0 bg-white dark:bg-gray-800 shadow dark:shadow-gray-700">
                    <button
                        type="button"
                        className="px-4 text-gray-500 dark:text-gray-400 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 lg:hidden"
                        onClick={() => setSidebarOpen(true)}
                    >
                        <Menu className="h-6 w-6" />
                    </button>
                    <div className="flex flex-1 justify-between px-4">
                        <div className="flex flex-1 items-center">
                            {/* Breadcrumbs or search could go here */}
                        </div>
                        <div className="ml-4 flex items-center gap-2 md:ml-6">
                            <div
                                ref={userMenuRef}
                                className="relative -ml-4 pl-4"
                                onPointerEnter={(e) => {
                                    if (e.pointerType !== 'mouse') return;
                                    setUserMenuPinned(false);
                                    setUserMenuOpen(true);
                                }}
                            >
                                <button
                                    type="button"
                                    title={me?.username || 'User'}
                                    aria-haspopup="menu"
                                    aria-expanded={userMenuOpen}
                                    className="inline-flex items-center justify-center h-10 w-10 rounded-full text-gray-700 hover:text-gray-900 hover:bg-gray-100 dark:text-gray-200 dark:hover:text-white dark:hover:bg-gray-700"
                                    onPointerDown={(e) => {
                                        e.stopPropagation();
                                        // Desktop behavior is hover-driven. Click-to-toggle is for touch.
                                        if (e.pointerType === 'mouse') return;
                                        setUserMenuPinned(true);
                                        setUserMenuOpen((v) => !v);
                                    }}
                                >
                                    <User className="h-5 w-5" />
                                </button>

                                <div
                                    className={`absolute right-0 top-full pt-2 ${userMenuOpen ? 'block' : 'hidden'}`}
                                    ref={userMenuDropdownRef}
                                >
                                    <div className="w-48 rounded-md shadow bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5">
                                        <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700">
                                            <div className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                                                {me?.username || 'User'}
                                            </div>
                                        </div>
                                        <button
                                            type="button"
                                            onClick={handleLogout}
                                            className="w-full flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-200 dark:hover:bg-gray-700 dark:hover:text-white"
                                        >
                                            <LogOut className="h-4 w-4 mr-2" />
                                            Logout
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div className="lg:hidden">
                                <ThemeToggle />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Page content */}
                <main className="flex-1">
                    <div className="py-6">
                        <div className="mx-auto max-w-7xl px-4 sm:px-6 md:px-8">
                            <Outlet />
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
}
