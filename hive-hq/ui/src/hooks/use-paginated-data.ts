import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import apiClient from '@/lib/api-client';
import type { PaginatedResponse } from '@/types';

const PAGE_SIZE = 50;

export interface UsePaginatedDataOptions<T> {
    /** The API endpoint to fetch data from */
    endpoint: string;
    /** Whether the hook is enabled */
    enabled?: boolean;
    /** Optional key extractor for deduplication */
    keyExtractor?: (item: T) => string;
}

export interface UsePaginatedDataResult<T> {
    /** All loaded data (cached across pages) */
    data: T[];
    /** Whether initial data is loading */
    isLoading: boolean;
    /** Whether more data is being loaded in background */
    isLoadingMore: boolean;
    /** Whether all data has been loaded */
    allLoaded: boolean;
    /** Total number of items loaded */
    totalLoaded: number;
    /** Refetch all data from scratch */
    refetch: () => void;
    /** Error if any occurred */
    error: Error | null;
}

/**
 * Hook that progressively loads all paginated data and caches it.
 * This enables proper client-side search across all data.
 */
export function usePaginatedData<T>({
    endpoint,
    enabled = true,
    keyExtractor,
}: UsePaginatedDataOptions<T>): UsePaginatedDataResult<T> {
    const [data, setData] = useState<T[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [allLoaded, setAllLoaded] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    const [fetchTrigger, setFetchTrigger] = useState(0);

    // Use refs to avoid dependency issues with callbacks
    const keyExtractorRef = useRef(keyExtractor);
    keyExtractorRef.current = keyExtractor;

    // Track if we're currently loading to prevent duplicate fetches
    const isLoadingRef = useRef(false);

    const loadAllData = useCallback(async () => {
        if (!enabled || isLoadingRef.current) return;

        isLoadingRef.current = true;
        setIsLoading(true);
        setError(null);
        setAllLoaded(false);

        try {
            // Load first page
            const firstResponse = await apiClient.get<PaginatedResponse<T> | T[]>(endpoint, {
                params: { limit: PAGE_SIZE, offset: 0 },
            });

            // Detect if response is paginated or plain array
            const isPaginated = firstResponse.data &&
                typeof firstResponse.data === 'object' &&
                !Array.isArray(firstResponse.data) &&
                'data' in firstResponse.data &&
                'total' in firstResponse.data;

            if (isPaginated) {
                // Handle PaginatedResponse
                const paginatedData = firstResponse.data as PaginatedResponse<T>;
                let allData = paginatedData.data;
                const total = paginatedData.total;
                setData(allData);
                setIsLoading(false);

                // Check if we've loaded all data
                if (allData.length >= total || paginatedData.data.length < PAGE_SIZE) {
                    setAllLoaded(true);
                    isLoadingRef.current = false;
                    return;
                }

                // Load remaining pages in background
                setIsLoadingMore(true);
                let offset = PAGE_SIZE;

                while (allData.length < total) {
                    const response = await apiClient.get<PaginatedResponse<T>>(endpoint, {
                        params: { limit: PAGE_SIZE, offset },
                    });

                    const newItems = response.data.data;

                    if (newItems.length > 0) {
                        // Deduplicate if keyExtractor is provided
                        const extractor = keyExtractorRef.current;
                        if (extractor) {
                            const existingKeys = new Set(allData.map(extractor));
                            const uniqueNewItems = newItems.filter(item => !existingKeys.has(extractor(item)));
                            allData = [...allData, ...uniqueNewItems];
                        } else {
                            allData = [...allData, ...newItems];
                        }
                        setData(allData);
                    }

                    if (newItems.length < PAGE_SIZE || allData.length >= total) {
                        break;
                    }
                    offset += PAGE_SIZE;
                }
            } else {
                // Handle plain array response - may need to load more pages
                let arrayData = firstResponse.data as T[];
                setData(arrayData);
                setIsLoading(false);

                // If we got exactly PAGE_SIZE items, there might be more
                if (arrayData.length === PAGE_SIZE) {
                    setIsLoadingMore(true);
                    let offset = PAGE_SIZE;
                    let hasMore = true;

                    while (hasMore) {
                        const response = await apiClient.get<T[]>(endpoint, {
                            params: { limit: PAGE_SIZE, offset },
                        });

                        const newItems = response.data;

                        if (newItems.length > 0) {
                            // Deduplicate if keyExtractor is provided
                            const extractor = keyExtractorRef.current;
                            if (extractor) {
                                const existingKeys = new Set(arrayData.map(extractor));
                                const uniqueNewItems = newItems.filter(item => !existingKeys.has(extractor(item)));
                                arrayData = [...arrayData, ...uniqueNewItems];
                            } else {
                                arrayData = [...arrayData, ...newItems];
                            }
                            setData(arrayData);
                        }

                        hasMore = newItems.length === PAGE_SIZE;
                        offset += PAGE_SIZE;
                    }
                }
            }

            setAllLoaded(true);
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to load data'));
            console.error('Error loading paginated data:', err);
        } finally {
            setIsLoading(false);
            setIsLoadingMore(false);
            isLoadingRef.current = false;
        }
    }, [endpoint, enabled]); // Remove keyExtractor from deps - use ref instead

    // Load data on mount and when dependencies change
    useEffect(() => {
        loadAllData();
    }, [loadAllData, fetchTrigger]);

    const refetch = useCallback(() => {
        isLoadingRef.current = false; // Allow refetch
        setData([]);
        setFetchTrigger(prev => prev + 1);
    }, []);

    return {
        data,
        isLoading,
        isLoadingMore,
        allLoaded,
        totalLoaded: data.length,
        refetch,
        error,
    };
}

/**
 * Filters data based on a search query across multiple fields
 */
export function useFilteredData<T>(
    data: T[],
    searchQuery: string,
    getSearchableValues: (item: T) => (string | null | undefined)[]
): T[] {
    return useMemo(() => {
        if (!searchQuery.trim()) return data;

        const query = searchQuery.toLowerCase().trim();
        return data.filter(item => {
            const values = getSearchableValues(item);
            return values.some(value =>
                value && String(value).toLowerCase().includes(query)
            );
        });
    }, [data, searchQuery, getSearchableValues]);
}

/**
 * Paginates filtered data for display with proper page counts
 */
export function usePaginatedDisplay<T>(
    filteredData: T[],
    page: number,
    pageSize: number = PAGE_SIZE
): {
    displayData: T[];
    totalPages: number;
    totalItems: number;
    startIndex: number;
    endIndex: number;
} {
    return useMemo(() => {
        const totalItems = filteredData.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
        const startIndex = (page - 1) * pageSize;
        const endIndex = Math.min(startIndex + pageSize, totalItems);
        const displayData = filteredData.slice(startIndex, endIndex);

        return {
            displayData,
            totalPages,
            totalItems,
            startIndex,
            endIndex,
        };
    }, [filteredData, page, pageSize]);
}
