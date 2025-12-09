import { Link } from 'react-router-dom';
import { Server, Layers, FolderGit2, GitBranch } from 'lucide-react';
import { PageHeader } from '@/components';
import { useClusters, useRepos, useServiceDefinitions, useClusterGroups } from '@/hooks';

export function HomePage() {
    const { data: clusters } = useClusters({ limit: 5, offset: 0 });
    const { data: repos } = useRepos({ limit: 5, offset: 0 });
    const { data: services } = useServiceDefinitions({ limit: 5, offset: 0 });
    const { data: clusterGroups } = useClusterGroups({ limit: 5, offset: 0 });

    const stats = [
        {
            name: 'Total Clusters',
            value: clusters?.total ?? '-',
            icon: Server,
            href: '/clusters',
            color: 'bg-blue-500',
        },
        {
            name: 'Services',
            value: services?.total ?? '-',
            icon: Layers,
            href: '/services',
            color: 'bg-green-500',
        },
        {
            name: 'Repositories',
            value: repos?.total ?? '-',
            icon: FolderGit2,
            href: '/repos',
            color: 'bg-purple-500',
        },
        {
            name: 'Cluster Groups',
            value: clusterGroups?.total ?? '-',
            icon: GitBranch,
            href: '/cluster-groups',
            color: 'bg-orange-500',
        },
    ];

    return (
        <div>
            <PageHeader
                title="Dashboard"
                description="Welcome to BeeCD HiveHQ - Manage your GitOps deployments"
            />

            {/* Stats Grid */}
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4 mb-8">
                {stats.map((stat) => (
                    <Link
                        key={stat.name}
                        to={stat.href}
                        className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg hover:shadow-md transition-shadow"
                    >
                        <div className="p-5">
                            <div className="flex items-center">
                                <div className={`flex-shrink-0 ${stat.color} rounded-md p-3`}>
                                    <stat.icon className="h-6 w-6 text-white" />
                                </div>
                                <div className="ml-5 w-0 flex-1">
                                    <dl>
                                        <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                                            {stat.name}
                                        </dt>
                                        <dd className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                                            {stat.value}
                                        </dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                    </Link>
                ))}
            </div>

            {/* Quick Actions */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 mb-8">
                <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Quick Actions</h2>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    <Link
                        to="/clusters"
                        className="relative block p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-blue-500 hover:ring-1 hover:ring-blue-500 transition-all"
                    >
                        <div className="flex items-center">
                            <Server className="h-8 w-8 text-blue-500" />
                            <div className="ml-4">
                                <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">View Clusters</h3>
                                <p className="text-sm text-gray-500 dark:text-gray-400">Manage your Kubernetes clusters</p>
                            </div>
                        </div>
                    </Link>
                    <Link
                        to="/services"
                        className="relative block p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-green-500 hover:ring-1 hover:ring-green-500 transition-all"
                    >
                        <div className="flex items-center">
                            <Layers className="h-8 w-8 text-green-500" />
                            <div className="ml-4">
                                <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">View Services</h3>
                                <p className="text-sm text-gray-500 dark:text-gray-400">Manage service definitions</p>
                            </div>
                        </div>
                    </Link>
                    <Link
                        to="/repos"
                        className="relative block p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-purple-500 hover:ring-1 hover:ring-purple-500 transition-all"
                    >
                        <div className="flex items-center">
                            <FolderGit2 className="h-8 w-8 text-purple-500" />
                            <div className="ml-4">
                                <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">View Repositories</h3>
                                <p className="text-sm text-gray-500 dark:text-gray-400">Manage Git repositories</p>
                            </div>
                        </div>
                    </Link>
                </div>
            </div>

            {/* Recent Activity Placeholder */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
                <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Recent Activity</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    Activity feed coming soon...
                </p>
            </div>
        </div>
    );
}
