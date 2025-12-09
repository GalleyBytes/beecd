import { useState, useCallback } from 'react';
import type { PaginationParams } from '@/types';

interface UsePaginationOptions {
    initialLimit?: number;
    initialOffset?: number;
}

interface UsePaginationReturn {
    params: PaginationParams;
    page: number;
    limit: number;
    setPage: (page: number) => void;
    setLimit: (limit: number) => void;
    nextPage: () => void;
    prevPage: () => void;
    reset: () => void;
    totalPages: (total: number) => number;
}

export function usePagination(options: UsePaginationOptions = {}): UsePaginationReturn {
    const { initialLimit = 50, initialOffset = 0 } = options;

    const [limit, setLimitState] = useState(initialLimit);
    const [offset, setOffset] = useState(initialOffset);

    const page = Math.floor(offset / limit) + 1;

    const setPage = useCallback((newPage: number) => {
        setOffset((newPage - 1) * limit);
    }, [limit]);

    const setLimit = useCallback((newLimit: number) => {
        setLimitState(newLimit);
        setOffset(0); // Reset to first page when changing limit
    }, []);

    const nextPage = useCallback(() => {
        setOffset((prev) => prev + limit);
    }, [limit]);

    const prevPage = useCallback(() => {
        setOffset((prev) => Math.max(0, prev - limit));
    }, [limit]);

    const reset = useCallback(() => {
        setOffset(0);
        setLimitState(initialLimit);
    }, [initialLimit]);

    const totalPages = useCallback((total: number) => {
        return Math.ceil(total / limit);
    }, [limit]);

    return {
        params: { limit, offset },
        page,
        limit,
        setPage,
        setLimit,
        nextPage,
        prevPage,
        reset,
        totalPages,
    };
}
