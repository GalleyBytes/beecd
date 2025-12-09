import { type ReactNode, useState, useMemo, useEffect } from 'react';
import { Search, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight } from 'lucide-react';

export interface Column<T> {
    key: string;
    header: string;
    render?: (item: T) => ReactNode;
    sortable?: boolean;
    searchable?: boolean;
    className?: string;
    // For getting the raw value for sorting/searching
    getValue?: (item: T) => string | number | null;
}

type SortDirection = 'asc' | 'desc' | null;

interface DataTableProps<T> {
    data: T[];
    columns: Column<T>[];
    keyExtractor: (item: T) => string;
    isLoading?: boolean;
    emptyMessage?: string;
    onRowClick?: (item: T) => void;
    searchPlaceholder?: string;
    // If true, search is handled server-side (via onSearch callback)
    serverSearch?: boolean;
    onSearch?: (query: string) => void;
    // If true, sorting is handled server-side (via onSort callback)
    serverSort?: boolean;
    onSort?: (key: string, direction: SortDirection) => void;
    // Pagination props
    pageSize?: number;
    showPagination?: boolean;
    // Loading more indicator
    isLoadingMore?: boolean;
    allLoaded?: boolean;
    totalItems?: number;
}

export function DataTable<T>({
    data,
    columns,
    keyExtractor,
    isLoading = false,
    emptyMessage = 'No data available',
    onRowClick,
    searchPlaceholder = 'Search...',
    serverSearch = false,
    onSearch,
    serverSort = false,
    onSort,
    pageSize = 10,
    showPagination = true,
    isLoadingMore = false,
    allLoaded = true,
    totalItems,
}: DataTableProps<T>) {
    const [searchQuery, setSearchQuery] = useState('');
    const [sortKey, setSortKey] = useState<string | null>(null);
    const [sortDirection, setSortDirection] = useState<SortDirection>(null);
    const [currentPage, setCurrentPage] = useState(1);
    const [currentPageSize, setCurrentPageSize] = useState(pageSize);

    // Handle search input change
    const handleSearchChange = (value: string) => {
        setSearchQuery(value);
        setCurrentPage(1); // Reset to first page on search
        if (serverSearch && onSearch) {
            onSearch(value);
        }
    };

    // Handle page size change
    const handlePageSizeChange = (newSize: number) => {
        setCurrentPageSize(newSize);
        setCurrentPage(1); // Reset to first page when changing page size
    };

    // Handle column sort click
    const handleSort = (columnKey: string) => {
        let newDirection: SortDirection;

        if (sortKey !== columnKey) {
            newDirection = 'asc';
        } else if (sortDirection === 'asc') {
            newDirection = 'desc';
        } else if (sortDirection === 'desc') {
            newDirection = null;
        } else {
            newDirection = 'asc';
        }

        setSortKey(newDirection ? columnKey : null);
        setSortDirection(newDirection);

        if (serverSort && onSort) {
            onSort(columnKey, newDirection);
        }
    };

    // Get the raw value from an item for a column
    const getRawValue = (item: T, column: Column<T>): string | number | null => {
        if (column.getValue) {
            return column.getValue(item);
        }
        const value = (item as Record<string, unknown>)[column.key];
        if (value === null || value === undefined) return null;
        if (typeof value === 'string' || typeof value === 'number') return value;
        return String(value);
    };

    // Filter and sort data locally (when not using server-side)
    const processedData = useMemo(() => {
        let result = [...data];

        // Client-side search
        if (!serverSearch && searchQuery.trim()) {
            const query = searchQuery.toLowerCase().trim();
            const searchableColumns = columns.filter(c => c.searchable !== false);

            result = result.filter(item => {
                return searchableColumns.some(column => {
                    const value = getRawValue(item, column);
                    if (value === null) return false;
                    return String(value).toLowerCase().includes(query);
                });
            });
        }

        // Client-side sort
        if (!serverSort && sortKey && sortDirection) {
            const column = columns.find(c => c.key === sortKey);
            if (column) {
                result.sort((a, b) => {
                    const aVal = getRawValue(a, column);
                    const bVal = getRawValue(b, column);

                    // Handle nulls
                    if (aVal === null && bVal === null) return 0;
                    if (aVal === null) return sortDirection === 'asc' ? 1 : -1;
                    if (bVal === null) return sortDirection === 'asc' ? -1 : 1;

                    // Compare values
                    let comparison = 0;
                    if (typeof aVal === 'number' && typeof bVal === 'number') {
                        comparison = aVal - bVal;
                    } else {
                        comparison = String(aVal).localeCompare(String(bVal));
                    }

                    return sortDirection === 'asc' ? comparison : -comparison;
                });
            }
        }

        return result;
    }, [data, searchQuery, sortKey, sortDirection, columns, serverSearch, serverSort]);

    // Calculate paginated data
    const { paginatedData, totalPages, totalCount, startIndex, endIndex, effectivePage } = useMemo(() => {
        const totalCount = processedData.length;
        const totalPages = Math.max(1, Math.ceil(totalCount / currentPageSize));
        // Auto-correct page if it's out of bounds
        const effectivePage = Math.min(currentPage, totalPages);
        const startIndex = (effectivePage - 1) * currentPageSize;
        const endIndex = Math.min(startIndex + currentPageSize, totalCount);
        const paginatedData = showPagination
            ? processedData.slice(startIndex, endIndex)
            : processedData;

        return { paginatedData, totalPages, totalCount, startIndex, endIndex, effectivePage };
    }, [processedData, currentPage, currentPageSize, showPagination]);

    // Sync currentPage with effectivePage if they differ
    useEffect(() => {
        if (currentPage !== effectivePage) {
            setCurrentPage(effectivePage);
        }
    }, [currentPage, effectivePage]);

    // Check if any column is sortable
    const hasSortableColumns = columns.some(c => c.sortable);
    // Check if any column is searchable (default to true)
    const hasSearchableColumns = columns.some(c => c.searchable !== false);

    const renderSortIcon = (columnKey: string, isSortable: boolean) => {
        if (!isSortable) return null;

        if (sortKey !== columnKey) {
            return <ChevronsUpDown className="w-4 h-4 ml-1 opacity-40" />;
        }

        if (sortDirection === 'asc') {
            return <ChevronUp className="w-4 h-4 ml-1" />;
        }
        if (sortDirection === 'desc') {
            return <ChevronDown className="w-4 h-4 ml-1" />;
        }

        return <ChevronsUpDown className="w-4 h-4 ml-1 opacity-40" />;
    };

    return (
        <div>
            {/* Search bar */}
            {hasSearchableColumns && (
                <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                    <div className="relative max-w-md">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <Search className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                        </div>
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => handleSearchChange(e.target.value)}
                            placeholder={searchPlaceholder}
                            className="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md leading-5 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 text-sm"
                        />
                        {searchQuery && (
                            <button
                                onClick={() => handleSearchChange('')}
                                className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                            >
                                ×
                            </button>
                        )}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                        {!serverSearch && (
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                {searchQuery
                                    ? `Showing ${startIndex + 1}-${endIndex} of ${totalCount} filtered results`
                                    : `Showing ${startIndex + 1}-${endIndex} of ${totalItems ?? totalCount} results`
                                }
                            </p>
                        )}
                        {isLoadingMore && (
                            <span className="text-xs text-blue-500 dark:text-blue-400 flex items-center">
                                <span className="animate-spin h-3 w-3 border-2 border-blue-500 border-t-transparent rounded-full mr-1"></span>
                                Loading more...
                            </span>
                        )}
                        {!allLoaded && !isLoadingMore && (
                            <span className="text-xs text-gray-400 dark:text-gray-500">
                                (more data available)
                            </span>
                        )}
                    </div>
                </div>
            )}

            {/* Loading state */}
            {isLoading ? (
                <div className="flex items-center justify-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    <span className="ml-3 text-gray-600 dark:text-gray-400">Loading...</span>
                </div>
            ) : processedData.length === 0 ? (
                <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                    {searchQuery ? `No results for "${searchQuery}"` : emptyMessage}
                </div>
            ) : (
                <>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-900">
                                <tr>
                                    {columns.map((column) => {
                                        const isSortable = column.sortable ?? hasSortableColumns;
                                        return (
                                            <th
                                                key={column.key}
                                                scope="col"
                                                onClick={() => isSortable && handleSort(column.key)}
                                                className={`px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider ${column.className || ''
                                                    } ${isSortable ? 'cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 select-none' : ''}`}
                                            >
                                                <div className="flex items-center">
                                                    {column.header}
                                                    {renderSortIcon(column.key, isSortable)}
                                                </div>
                                            </th>
                                        );
                                    })}
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {paginatedData.map((item) => (
                                    <tr
                                        key={keyExtractor(item)}
                                        onClick={() => onRowClick?.(item)}
                                        className={onRowClick ? 'hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer' : ''}
                                    >
                                        {columns.map((column) => {
                                            // Determine what to render: custom render, getValue, or direct key access
                                            let content: ReactNode;
                                            if (column.render) {
                                                content = column.render(item);
                                            } else if (column.getValue) {
                                                const value = column.getValue(item);
                                                content = value !== null && value !== undefined ? String(value) : '-';
                                            } else {
                                                const value = (item as Record<string, unknown>)[column.key];
                                                content = value !== null && value !== undefined ? String(value) : '-';
                                            }

                                            return (
                                                <td
                                                    key={`${keyExtractor(item)}-${column.key}`}
                                                    className={`px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100 ${column.className || ''}`}
                                                >
                                                    {content}
                                                </td>
                                            );
                                        })}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination controls */}
                    {showPagination && totalPages > 1 && (
                        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
                            <div className="flex items-center gap-4">
                                <span className="text-sm text-gray-500 dark:text-gray-400">
                                    Showing {startIndex + 1}-{endIndex} of {totalCount}
                                </span>
                                <select
                                    value={currentPageSize}
                                    onChange={(e) => handlePageSizeChange(Number(e.target.value))}
                                    className="rounded border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 text-sm focus:ring-blue-500 focus:border-blue-500"
                                >
                                    <option value={10}>10 per page</option>
                                    <option value={25}>25 per page</option>
                                    <option value={50}>50 per page</option>
                                    <option value={100}>100 per page</option>
                                </select>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className="text-sm text-gray-500 dark:text-gray-400">
                                    Page {effectivePage} of {totalPages}
                                </span>
                                <button
                                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                                    disabled={effectivePage === 1}
                                    className="p-2 rounded-md border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
                                >
                                    <ChevronLeft className="w-4 h-4" />
                                </button>

                                {/* Page number buttons */}
                                <div className="flex gap-1">
                                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                                        let pageNum: number;
                                        if (totalPages <= 5) {
                                            pageNum = i + 1;
                                        } else if (effectivePage <= 3) {
                                            pageNum = i + 1;
                                        } else if (effectivePage >= totalPages - 2) {
                                            pageNum = totalPages - 4 + i;
                                        } else {
                                            pageNum = effectivePage - 2 + i;
                                        }
                                        return (
                                            <button
                                                key={pageNum}
                                                onClick={() => setCurrentPage(pageNum)}
                                                className={`px-3 py-1 rounded-md text-sm ${effectivePage === pageNum
                                                    ? 'bg-blue-600 text-white'
                                                    : 'border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'
                                                    }`}
                                            >
                                                {pageNum}
                                            </button>
                                        );
                                    })}
                                </div>

                                <button
                                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                                    disabled={effectivePage === totalPages}
                                    className="p-2 rounded-md border border-gray-300 dark:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
                                >
                                    <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
