import type { ReactNode } from 'react';

interface PageHeaderProps {
    title: string;
    description?: ReactNode;
    actions?: ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
    return (
        <div className="md:flex md:items-center md:justify-between mb-8">
            <div className="min-w-0 flex-1">
                <h1 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:truncate sm:text-3xl sm:tracking-tight">
                    {title}
                </h1>
                {description && (
                    <div className="mt-1 text-sm text-gray-500 dark:text-gray-400">{description}</div>
                )}
            </div>
            {actions && (
                <div className="mt-4 flex md:ml-4 md:mt-0 space-x-3">
                    {actions}
                </div>
            )}
        </div>
    );
}
