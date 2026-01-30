import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import apiClient from '@/lib/api-client';

interface AppConfig {
    version: string;
    baseDomain: string | null;
}

interface ConfigContextType {
    config: AppConfig | null;
    loading: boolean;
    error: string | null;
}

const ConfigContext = createContext<ConfigContextType | undefined>(undefined);

export function ConfigProvider({ children }: { children: ReactNode }) {
    const [config, setConfig] = useState<AppConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const response = await apiClient.get('/config');
                setConfig({
                    version: response.data.version,
                    baseDomain: response.data.base_domain ?? null,
                });
            } catch (err) {
                console.error('Failed to fetch app config:', err);
                setError('Failed to load configuration');
            } finally {
                setLoading(false);
            }
        };

        fetchConfig();
    }, []);

    return (
        <ConfigContext.Provider value={{ config, loading, error }}>
            {children}
        </ConfigContext.Provider>
    );
}

export function useConfig(): ConfigContextType {
    const context = useContext(ConfigContext);
    if (context === undefined) {
        throw new Error('useConfig must be used within a ConfigProvider');
    }
    return context;
}

/**
 * Extract tenant slug from the current hostname using the configured base domain.
 * 
 * With baseDomain = "beecd.example.com":
 *   - "tenant1.beecd.example.com" → "tenant1"
 *   - "beecd.example.com" → null (base domain, no tenant)
 * 
 * Without baseDomain (fallback):
 *   - "tenant1.localhost" → "tenant1"
 *   - "localhost" → null
 */
export function useCurrentTenant(): string | null {
    const { config } = useConfig();
    const host = window.location.hostname.toLowerCase();

    if (config?.baseDomain) {
        const base = config.baseDomain.toLowerCase();
        // If host ends with .baseDomain, extract the subdomain
        if (host.endsWith(`.${base}`)) {
            const prefix = host.slice(0, host.length - base.length - 1);
            // Get the rightmost label (closest to base domain)
            const parts = prefix.split('.');
            return parts[parts.length - 1] || null;
        }
        // If host equals baseDomain exactly, no tenant
        if (host === base) {
            return null;
        }
    }

    // Fallback: first label if not localhost
    const parts = host.split('.');
    if (parts.length >= 2 && parts[0] !== 'localhost') {
        return parts[0];
    }

    return null;
}

/**
 * Construct a URL for a tenant subdomain.
 * Uses the configured base domain if available, otherwise uses current hostname.
 */
export function useTenantUrl(): (slug: string, path?: string) => string {
    const { config } = useConfig();

    return (slug: string, path: string = '/') => {
        const protocol = window.location.protocol;
        const port = window.location.port ? `:${window.location.port}` : '';

        if (config?.baseDomain) {
            return `${protocol}//${slug}.${config.baseDomain}${port}${path}`;
        }

        // Fallback: use current hostname
        const baseDomain = window.location.hostname;
        return `${protocol}//${slug}.${baseDomain}${port}${path}`;
    };
}
