import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Check, X, FileCode, AlertTriangle, GitBranch, Clock, Package, History, RotateCcw, Pin, PinOff, Filter, Plus } from 'lucide-react';
import { PageHeader, Alert, Modal } from '@/components';
import { useRelease, useReleaseDiff, useApproveReleases, useUnapproveReleases, useReleaseVersions, useSelectServiceVersion, useRestoreLatestRelease, usePinServiceVersion, useUnpinServiceVersion, useCreateServiceVersion } from '@/hooks';
import type { ServiceVersionForRelease, CreateServiceVersion } from '@/types';

// Convert ANSI color codes to HTML spans with CSS colors
function convertAnsiToHtml(text: string): { html: string; added: number; removed: number } {
    let added = 0;
    let removed = 0;

    // Escape HTML entities first
    let html = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    // ANSI color code mappings
    const colorMap: Record<string, string> = {
        '30': '#000',      // black
        '31': '#ef4444',   // red (removals)
        '32': '#22c55e',   // green (additions)
        '33': '#eab308',   // yellow
        '34': '#3b82f6',   // blue
        '35': '#a855f7',   // magenta
        '36': '#06b6d4',   // cyan
        '37': '#f3f4f6',   // white
        '90': '#6b7280',   // bright black (gray)
        '91': '#f87171',   // bright red
        '92': '#4ade80',   // bright green
        '93': '#facc15',   // bright yellow
        '94': '#60a5fa',   // bright blue
        '95': '#c084fc',   // bright magenta
        '96': '#22d3ee',   // bright cyan
        '97': '#ffffff',   // bright white
    };

    // Track open spans for proper nesting
    let spanOpen = false;

    // Replace ANSI codes with HTML spans
    // Match patterns like \x1b[0m, \x1b[32m, \x1b[1;32m, etc.
    html = html.replace(/\x1b\[([0-9;]*)m/g, (_, codes) => {
        const codeList = codes.split(';').filter(Boolean);

        // Reset code (0 or empty)
        if (codeList.length === 0 || codeList.includes('0')) {
            if (spanOpen) {
                spanOpen = false;
                return '</span>';
            }
            return '';
        }

        // Find color code
        for (const code of codeList) {
            if (colorMap[code]) {
                const color = colorMap[code];
                const result = (spanOpen ? '</span>' : '') + `<span style="color:${color}">`;
                spanOpen = true;

                // Count additions/removals for summary
                if (code === '32' || code === '92') added++;
                if (code === '31' || code === '91') removed++;

                return result;
            }
        }

        return '';
    });

    // Close any remaining open span
    if (spanOpen) {
        html += '</span>';
    }

    return { html, added, removed };
}

function formatRelativeTime(dateString: string): string {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

function StatusBadge({ status }: { status: string }) {
    const statusColors: Record<string, string> = {
        'InstalledUpToDate': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        'Installed': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        'Installing': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        'DriftRepairsInstalling': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        'PendingApproval': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        'PendingAgentInstallation': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        'InstallFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'DriftRepairsFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'DeleteFailed': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        'Deleting': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
        'Deleted': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
        'Uninitiated': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    };

    const colorClass = statusColors[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';

    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
            {status}
        </span>
    );
}

// Diff viewer modal component
function DiffViewerModal({
    isOpen,
    onClose,
    diffs,
    isLoading,
    error,
}: {
    isOpen: boolean;
    onClose: () => void;
    // Note: Rust uses #[serde(flatten)] so diff_data fields are at root level
    diffs: Array<{ body: string; key?: string; storage_url?: string | null }>;
    isLoading: boolean;
    error: Error | null;
}) {
    const [selectedDiff, setSelectedDiff] = useState(0);

    // Reset selected diff when diffs change
    useEffect(() => {
        setSelectedDiff(0);
    }, [diffs]);

    if (!isOpen) return null;

    // Parse diff key in format: {kind}/{namespace}/{name}
    // e.g., "Deployment/default/my-app" -> { kind: "Deployment", namespace: "default", name: "my-app" }
    const parseDiffKey = (key: string | undefined) => {
        if (!key) return { kind: 'Resource', namespace: '', name: 'Unknown' };
        const parts = key.split('/');
        if (parts.length >= 3) {
            return { kind: parts[0], namespace: parts[1], name: parts.slice(2).join('/') };
        } else if (parts.length === 2) {
            return { kind: parts[0], namespace: '', name: parts[1] };
        }
        return { kind: 'Resource', namespace: '', name: key };
    };

    // Safely get diff display name (key is at root due to serde flatten)
    const getDiffName = (diff: typeof diffs[0]) => {
        const parsed = parseDiffKey(diff?.key);
        return parsed.name || 'Unknown Resource';
    };

    const getDiffKind = (diff: typeof diffs[0]) => {
        const parsed = parseDiffKey(diff?.key);
        return parsed.kind || 'Resource';
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop - clicking closes modal */}
            <div
                className="fixed inset-0 bg-black/50 dark:bg-black/70"
                onClick={onClose}
            />
            {/* Modal content */}
            <div className="relative z-10 w-full max-w-5xl bg-white dark:bg-gray-800 rounded-lg shadow-xl max-h-[85vh] flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex-shrink-0">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Release Diff
                    </h3>
                    <button
                        onClick={onClose}
                        className="rounded-md p-2 text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-500 dark:hover:text-gray-300"
                    >
                        <span className="sr-only">Close</span>
                        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                {/* Body */}
                <div className="flex-1 overflow-hidden">
                    {isLoading ? (
                        <div className="flex items-center justify-center h-64">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                            <span className="ml-2 text-gray-600 dark:text-gray-400">Loading diffs...</span>
                        </div>
                    ) : error ? (
                        <div className="p-4">
                            <Alert type="error" title="Failed to load diffs" message={error.message} />
                        </div>
                    ) : !diffs || diffs.length === 0 ? (
                        <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
                            No diffs available for this release
                        </div>
                    ) : (
                        <div className="flex h-[60vh]">
                            {/* Sidebar with diff list */}
                            <div className="w-64 flex-shrink-0 border-r border-gray-200 dark:border-gray-700 overflow-y-auto">
                                <div className="p-2 text-sm font-medium text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-700">
                                    Resources ({diffs.length})
                                </div>
                                {diffs.map((diff, index) => {
                                    const { added, removed } = convertAnsiToHtml(diff.body || '');
                                    const counts = (added > 0 || removed > 0) ? ` (+${added}/-${removed})` : '';
                                    return (
                                        <button
                                            key={index}
                                            onClick={() => setSelectedDiff(index)}
                                            className={`w-full text-left px-3 py-2 text-sm border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 ${selectedDiff === index ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' : 'text-gray-700 dark:text-gray-300'}`}
                                        >
                                            <div className="font-medium truncate">{getDiffName(diff)}{counts}</div>
                                            <div className="text-xs text-gray-500 dark:text-gray-400">{getDiffKind(diff)}</div>
                                        </button>
                                    );
                                })}
                            </div>
                            {/* Diff content */}
                            <div className="flex-1 overflow-auto bg-gray-900">
                                {diffs[selectedDiff] && diffs[selectedDiff].body && diffs[selectedDiff].body.trim() !== '' ? (
                                    <pre
                                        className="p-4 text-sm font-mono text-gray-100 whitespace-pre-wrap"
                                        dangerouslySetInnerHTML={{ __html: convertAnsiToHtml(diffs[selectedDiff].body).html }}
                                    />
                                ) : (
                                    <div className="flex items-center justify-center h-full text-gray-400">
                                        No changes in this resource
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// Add Manual Version Modal Component
function AddManualVersionModal({
    isOpen,
    onClose,
    onSubmit,
    isPending,
    releaseData,
    error,
}: {
    isOpen: boolean;
    onClose: () => void;
    onSubmit: (data: CreateServiceVersion) => void;
    isPending: boolean;
    releaseData: { service_definition_id: string; namespace_id: string; path: string } | null;
    error: Error | null;
}) {
    const [version, setVersion] = useState('');
    const [gitSha, setGitSha] = useState('');

    // Reset form when modal opens
    useEffect(() => {
        if (isOpen) {
            setVersion('');
            setGitSha('');
        }
    }, [isOpen]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!releaseData || !version.trim() || !gitSha.trim()) return;

        // Generate a simple hash from version + gitSha for manual versions
        const hash = `manual-${gitSha.substring(0, 8)}-${Date.now()}`;

        onSubmit({
            service_definition_id: releaseData.service_definition_id,
            namespace_id: releaseData.namespace_id,
            version: version.trim(),
            git_sha: gitSha.trim(),
            path: releaseData.path,
            hash,
            source: 'manual',
        });
    };

    const isValidGitSha = gitSha.length === 40 && /^[0-9a-fA-F]+$/.test(gitSha);
    const canSubmit = version.trim() && isValidGitSha && !isPending;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add Manual Version" size="md">
            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Create a new version manually. This version will become the active version
                        and any existing non-pinned version will be deprecated.
                    </p>

                    {error && (
                        <Alert
                            type="error"
                            title="Failed to create version"
                            message={error.message}
                        />
                    )}

                    <div>
                        <label htmlFor="version" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Version Tag
                        </label>
                        <input
                            type="text"
                            id="version"
                            value={version}
                            onChange={(e) => setVersion(e.target.value)}
                            placeholder="e.g., v1.0.0, release-2024-01-09"
                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                            A human-readable identifier for this version
                        </p>
                    </div>

                    <div>
                        <label htmlFor="gitSha" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Git Commit SHA
                        </label>
                        <input
                            type="text"
                            id="gitSha"
                            value={gitSha}
                            onChange={(e) => setGitSha(e.target.value)}
                            placeholder="e.g., a1b2c3d4e5f6..."
                            className={`w-full px-3 py-2 border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 text-sm font-mono focus:ring-blue-500 focus:border-blue-500 ${gitSha && !isValidGitSha
                                    ? 'border-red-300 dark:border-red-600'
                                    : 'border-gray-300 dark:border-gray-600'
                                }`}
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                            The full 40-character git commit SHA from your repository
                        </p>
                        {gitSha && !isValidGitSha && (
                            <p className="mt-1 text-xs text-red-600 dark:text-red-400">
                                Must be exactly 40 hexadecimal characters
                            </p>
                        )}
                    </div>
                </div>

                <div className="mt-6 flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={!canSubmit}
                        className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isPending ? 'Creating...' : 'Create Version'}
                    </button>
                </div>
            </form>
        </Modal>
    );
}

export function ReleaseDetailPage() {
    const { namespaceId, releaseName } = useParams<{ namespaceId: string; releaseName: string }>();
    const navigate = useNavigate();
    const [showDiffModal, setShowDiffModal] = useState(false);
    const [showVersionModal, setShowVersionModal] = useState(false);
    const [showAddVersionModal, setShowAddVersionModal] = useState(false);
    const [showDeployedOnly, setShowDeployedOnly] = useState(false);
    const [versionPage, setVersionPage] = useState(0);
    const versionsPerPage = 20;

    // Queries
    const { data: releaseStatus, isLoading, isError, error, refetch } = useRelease(namespaceId!, releaseName!);
    const { data: diffs = [], isLoading: loadingDiffs, error: diffError } = useReleaseDiff(
        releaseStatus?.data.id || '',
        releaseStatus?.data.diff_generation || 0,
        !!releaseStatus?.data.id && (releaseStatus?.data.diff_generation || 0) > 0
    );
    const { data: versionsData, isLoading: loadingVersions, refetch: refetchVersions } = useReleaseVersions(
        namespaceId!,
        releaseName!,
        { deployedOnly: showDeployedOnly, limit: versionsPerPage, offset: versionPage * versionsPerPage }
    );
    const releaseVersions = versionsData?.data ?? [];
    const totalVersions = versionsData?.total ?? 0;
    const totalPages = Math.ceil(totalVersions / versionsPerPage);

    // Mutations
    const approveReleases = useApproveReleases();
    const unapproveReleases = useUnapproveReleases();
    const selectVersion = useSelectServiceVersion();
    const restoreLatest = useRestoreLatestRelease();
    const pinVersion = usePinServiceVersion();
    const unpinVersion = useUnpinServiceVersion();
    const createVersion = useCreateServiceVersion();

    const handleCreateManualVersion = async (data: CreateServiceVersion) => {
        try {
            await createVersion.mutateAsync(data);
            setShowAddVersionModal(false);
            refetch();
            refetchVersions();
        } catch (err) {
            console.error('Failed to create manual version:', err);
        }
    };

    const handleApprove = async () => {
        if (!releaseStatus) return;
        try {
            await approveReleases.mutateAsync([releaseStatus.data.id]);
            refetch();
        } catch (err) {
            console.error('Failed to approve release:', err);
        }
    };

    const handleUnapprove = async () => {
        if (!releaseStatus) return;
        try {
            await unapproveReleases.mutateAsync([releaseStatus.data.id]);
            refetch();
        } catch (err) {
            console.error('Failed to unapprove release:', err);
        }
    };

    const handleSelectVersion = async (serviceVersionId: string) => {
        try {
            await selectVersion.mutateAsync(serviceVersionId);
            setShowVersionModal(false);
            refetch();
            refetchVersions();
        } catch (err) {
            console.error('Failed to select version:', err);
        }
    };

    const handlePinVersion = async (serviceVersionId: string) => {
        try {
            await pinVersion.mutateAsync(serviceVersionId);
            refetchVersions();
        } catch (err) {
            console.error('Failed to pin version:', err);
        }
    };

    const handleUnpinVersion = async (serviceVersionId: string) => {
        try {
            await unpinVersion.mutateAsync(serviceVersionId);
            refetchVersions();
        } catch (err) {
            console.error('Failed to unpin version:', err);
        }
    };

    const handleRestoreLatest = async () => {
        if (!namespaceId || !releaseName) return;
        try {
            await restoreLatest.mutateAsync({ namespaceId, releaseName });
            setShowVersionModal(false);
            refetch();
            refetchVersions();
        } catch (err) {
            console.error('Failed to restore latest:', err);
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    if (isError || !releaseStatus) {
        return (
            <div className="space-y-4">
                <button onClick={() => navigate(-1)} className="flex items-center text-blue-600 hover:text-blue-800">
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back
                </button>
                <Alert
                    type="error"
                    title="Failed to load release"
                    message={error instanceof Error ? error.message : 'Release not found'}
                />
            </div>
        );
    }

    const release = releaseStatus.data;
    const status = releaseStatus.status;
    const isPendingApproval = status === 'PendingApproval';
    const hasDiff = release.diff_generation > 0;

    return (
        <div className="space-y-6">
            {/* Diff Modal */}
            <DiffViewerModal
                isOpen={showDiffModal}
                onClose={() => setShowDiffModal(false)}
                diffs={diffs}
                isLoading={loadingDiffs}
                error={diffError}
            />

            {/* Add Manual Version Modal */}
            <AddManualVersionModal
                isOpen={showAddVersionModal}
                onClose={() => setShowAddVersionModal(false)}
                onSubmit={handleCreateManualVersion}
                isPending={createVersion.isPending}
                releaseData={{
                    service_definition_id: release.service_definition_id,
                    namespace_id: release.namespace_id,
                    path: release.path,
                }}
                error={createVersion.error}
            />

            {/* Version Selection Modal */}
            <Modal isOpen={showVersionModal} onClose={() => setShowVersionModal(false)} title="Manage Release Versions" size="lg">
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            <strong>Select</strong> a version to deploy it, or <strong>Pin</strong> versions to prevent them from being auto-deprecated when new commits are pushed.
                        </p>
                        <button
                            onClick={() => {
                                setShowVersionModal(false);
                                setShowAddVersionModal(true);
                            }}
                            className="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 whitespace-nowrap"
                        >
                            <Plus className="w-4 h-4 mr-1" />
                            Add Manual Version
                        </button>
                    </div>

                    {release.manually_selected_at && (
                        <div className="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
                            <span className="text-sm text-yellow-800 dark:text-yellow-200">
                                Currently using a manually selected version
                            </span>
                            <button
                                onClick={handleRestoreLatest}
                                disabled={restoreLatest.isPending}
                                className="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-md text-yellow-700 dark:text-yellow-300 bg-yellow-100 dark:bg-yellow-900/40 hover:bg-yellow-200 dark:hover:bg-yellow-900/60 disabled:opacity-50"
                            >
                                <RotateCcw className="w-4 h-4 mr-1" />
                                {restoreLatest.isPending ? 'Restoring...' : 'Use Latest'}
                            </button>
                        </div>
                    )}

                    {/* Filters */}
                    <div className="flex items-center gap-4 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                        <Filter className="w-4 h-4 text-gray-500" />
                        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                            <input
                                type="checkbox"
                                checked={showDeployedOnly}
                                onChange={(e) => {
                                    setShowDeployedOnly(e.target.checked);
                                    setVersionPage(0); // Reset to first page when filter changes
                                }}
                                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            Previously deployed only
                        </label>
                    </div>

                    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                        <div className="bg-gray-50 dark:bg-gray-800 px-4 py-2 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                Available Versions ({totalVersions})
                            </span>
                            {totalPages > 1 && (
                                <div className="flex items-center gap-2">
                                    <button
                                        onClick={() => setVersionPage(p => Math.max(0, p - 1))}
                                        disabled={versionPage === 0}
                                        className="px-2 py-1 text-xs font-medium rounded text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        ← Prev
                                    </button>
                                    <span className="text-xs text-gray-500 dark:text-gray-400">
                                        Page {versionPage + 1} of {totalPages}
                                    </span>
                                    <button
                                        onClick={() => setVersionPage(p => Math.min(totalPages - 1, p + 1))}
                                        disabled={versionPage >= totalPages - 1}
                                        className="px-2 py-1 text-xs font-medium rounded text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        Next →
                                    </button>
                                </div>
                            )}
                        </div>
                        {loadingVersions ? (
                            <div className="p-4 text-center">
                                <div className="animate-spin inline-block rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                            </div>
                        ) : releaseVersions.length === 0 ? (
                            <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                                No versions available
                            </div>
                        ) : (
                            <div className="max-h-80 overflow-y-auto divide-y divide-gray-200 dark:divide-gray-700">
                                {releaseVersions.map((version: ServiceVersionForRelease) => (
                                    <div
                                        key={version.id}
                                        className={`px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 ${version.is_current ? 'bg-blue-50 dark:bg-blue-900/20' : ''} ${version.deprecated_at ? 'opacity-60' : ''}`}
                                    >
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2">
                                                <span className="font-mono text-sm text-gray-900 dark:text-gray-100">
                                                    {version.git_sha_short || version.version || version.hash.substring(0, 8)}
                                                </span>
                                                {version.is_current && (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                                        Current
                                                    </span>
                                                )}
                                                {version.pinned_at && (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200" title={`Pinned by ${version.pinned_by || 'unknown'}`}>
                                                        <Pin className="w-3 h-3 mr-1" />
                                                        Pinned
                                                    </span>
                                                )}
                                                {version.deprecated_at && (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">
                                                        Deprecated
                                                    </span>
                                                )}
                                            </div>
                                            <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                                                Created {formatRelativeTime(version.created_at)}
                                                {version.last_deployed_at && (
                                                    <span className="ml-2 text-green-600 dark:text-green-400">
                                                        • Deployed {formatRelativeTime(version.last_deployed_at)}
                                                    </span>
                                                )}
                                                {version.source && ` • via ${version.source}`}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2 ml-4">
                                            {/* Pin/Unpin button */}
                                            {version.pinned_at ? (
                                                <button
                                                    onClick={() => handleUnpinVersion(version.id)}
                                                    disabled={unpinVersion.isPending}
                                                    className="inline-flex items-center px-2 py-1.5 text-sm font-medium rounded-md text-purple-700 dark:text-purple-300 bg-purple-100 dark:bg-purple-900/40 hover:bg-purple-200 dark:hover:bg-purple-900/60 disabled:opacity-50"
                                                    title="Unpin version (allow auto-deprecation)"
                                                >
                                                    <PinOff className="w-4 h-4" />
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() => handlePinVersion(version.id)}
                                                    disabled={pinVersion.isPending}
                                                    className="inline-flex items-center px-2 py-1.5 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-50"
                                                    title="Pin version (prevent auto-deprecation)"
                                                >
                                                    <Pin className="w-4 h-4" />
                                                </button>
                                            )}
                                            {/* Select button */}
                                            {!version.is_current && (
                                                <button
                                                    onClick={() => handleSelectVersion(version.id)}
                                                    disabled={selectVersion.isPending}
                                                    className="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-md text-blue-700 dark:text-blue-300 bg-blue-100 dark:bg-blue-900/40 hover:bg-blue-200 dark:hover:bg-blue-900/60 disabled:opacity-50"
                                                >
                                                    {selectVersion.isPending ? 'Selecting...' : 'Select'}
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </Modal>

            {/* Header with back button */}
            <div className="flex items-center justify-between">
                <button onClick={() => navigate(-1)} className="flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300">
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back
                </button>
                <button
                    onClick={() => refetch()}
                    className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                </button>
            </div>

            <PageHeader
                title={release.name}
                description={`Release in ${release.namespace} on ${release.cluster_name}`}
            />

            {/* Status and Actions Card */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-4">
                        <StatusBadge status={status} />
                        {release.total_errors > 0 && (
                            <span className="inline-flex items-center text-red-600 dark:text-red-400 text-sm">
                                <AlertTriangle className="w-4 h-4 mr-1" />
                                {release.total_errors} error{release.total_errors !== 1 ? 's' : ''}
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setShowVersionModal(true)}
                            className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                        >
                            <History className="w-4 h-4 mr-2" />
                            Versions
                            {release.manually_selected_at && (
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                                    Pinned
                                </span>
                            )}
                        </button>
                        <button
                            onClick={() => setShowDiffModal(true)}
                            disabled={!hasDiff}
                            title={!hasDiff ? 'Diffs have not been generated for this release yet' : 'View resource changes'}
                            className={`inline-flex items-center px-3 py-2 border text-sm font-medium rounded-md ${hasDiff
                                ? 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700'
                                : 'border-gray-200 dark:border-gray-700 text-gray-400 dark:text-gray-500 bg-gray-50 dark:bg-gray-800 cursor-not-allowed'
                                }`}
                        >
                            <FileCode className="w-4 h-4 mr-2" />
                            {hasDiff ? 'View Diff' : 'No Diff Available'}
                        </button>
                        {isPendingApproval && (
                            <button
                                onClick={handleApprove}
                                disabled={approveReleases.isPending}
                                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
                            >
                                <Check className="w-4 h-4 mr-2" />
                                {approveReleases.isPending ? 'Approving...' : 'Approve'}
                            </button>
                        )}
                        {!isPendingApproval && status !== 'Uninitiated' && (
                            <button
                                onClick={handleUnapprove}
                                disabled={unapproveReleases.isPending}
                                className="inline-flex items-center px-4 py-2 border border-red-300 dark:border-red-700 text-sm font-medium rounded-md text-red-700 dark:text-red-300 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50"
                            >
                                <X className="w-4 h-4 mr-2" />
                                {unapproveReleases.isPending ? 'Unapproving...' : 'Unapprove'}
                            </button>
                        )}
                    </div>
                </div>

                {/* Release Info Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Namespace</h4>
                        <p className="text-gray-900 dark:text-gray-100">{release.namespace}</p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Cluster</h4>
                        <Link
                            to={`/clusters/${release.cluster_id}`}
                            className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                        >
                            {release.cluster_name}
                        </Link>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Version</h4>
                        <p className="text-gray-900 dark:text-gray-100 font-mono text-sm">{release.version || '-'}</p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1 flex items-center">
                            <GitBranch className="w-4 h-4 mr-1" />
                            Branch
                        </h4>
                        <p className="text-gray-900 dark:text-gray-100">{release.branch}</p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1 flex items-center">
                            <Package className="w-4 h-4 mr-1" />
                            Repository
                        </h4>
                        <p className="text-gray-900 dark:text-gray-100">{release.org}/{release.repo}</p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Git SHA</h4>
                        <p className="text-gray-900 dark:text-gray-100 font-mono text-sm">{release.git_sha || '-'}</p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Hash</h4>
                        <p className="text-gray-900 dark:text-gray-100 font-mono text-sm truncate" title={release.hash}>
                            {release.hash || '-'}
                        </p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Path</h4>
                        <p className="text-gray-900 dark:text-gray-100 font-mono text-sm truncate" title={release.path}>
                            {release.path}
                        </p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1 flex items-center">
                            <Clock className="w-4 h-4 mr-1" />
                            Updated
                        </h4>
                        <p className="text-gray-900 dark:text-gray-100">
                            {release.updated_at ? formatRelativeTime(release.updated_at) : '-'}
                        </p>
                    </div>
                    <div>
                        <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">Approval Status</h4>
                        {(() => {
                            // Determine actual approval state based on timestamps
                            const hasApproval = release.approved_at != null;
                            const hasUnapproval = release.unapproved_at != null;

                            // If unapproved_at is set and (approved_at is null OR unapproved_at is more recent)
                            const isCurrentlyUnapproved = hasUnapproval && (!hasApproval ||
                                new Date(release.unapproved_at!) > new Date(release.approved_at!));

                            // If approved_at is set and (unapproved_at is null OR approved_at is more recent)
                            const isCurrentlyApproved = hasApproval && (!hasUnapproval ||
                                new Date(release.approved_at!) > new Date(release.unapproved_at!));

                            if (isCurrentlyUnapproved && release.unapproved_by) {
                                return (
                                    <p className="text-yellow-600 dark:text-yellow-400">
                                        Paused by {release.unapproved_by}
                                        {release.unapproved_at && (
                                            <span className="text-gray-500 dark:text-gray-400 text-sm ml-1">
                                                ({formatRelativeTime(release.unapproved_at)})
                                            </span>
                                        )}
                                        {release.unapproved_reason && (
                                            <span className="text-gray-500 dark:text-gray-400 text-sm ml-1">
                                                - {release.unapproved_reason}
                                            </span>
                                        )}
                                    </p>
                                );
                            } else if (isCurrentlyApproved && release.approved_by) {
                                return (
                                    <p className="text-green-600 dark:text-green-400">
                                        Approved by {release.approved_by}
                                        {release.approved_at && (
                                            <span className="text-gray-500 dark:text-gray-400 text-sm ml-1">
                                                ({formatRelativeTime(release.approved_at)})
                                            </span>
                                        )}
                                    </p>
                                );
                            } else {
                                return <p className="text-gray-500 dark:text-gray-400">Pending approval</p>;
                            }
                        })()}
                    </div>
                </div>
            </div>

            {/* Installation Timeline */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Installation Timeline</h3>
                <div className="space-y-4">
                    {release.started_first_install_at && (
                        <TimelineEvent
                            label="First Install Started"
                            time={release.started_first_install_at}
                            type="info"
                        />
                    )}
                    {release.completed_first_install_at && (
                        <TimelineEvent
                            label="First Install Completed"
                            time={release.completed_first_install_at}
                            type="success"
                        />
                    )}
                    {release.failed_first_install_at && (
                        <TimelineEvent
                            label="First Install Failed"
                            time={release.failed_first_install_at}
                            type="error"
                        />
                    )}
                    {release.started_update_install_at && (
                        <TimelineEvent
                            label="Update Started"
                            time={release.started_update_install_at}
                            type="info"
                        />
                    )}
                    {release.completed_update_install_at && (
                        <TimelineEvent
                            label="Update Completed"
                            time={release.completed_update_install_at}
                            type="success"
                        />
                    )}
                    {release.failed_update_install_at && (
                        <TimelineEvent
                            label="Update Failed"
                            time={release.failed_update_install_at}
                            type="error"
                        />
                    )}
                    {release.last_sync_at && (
                        <TimelineEvent
                            label="Last Sync"
                            time={release.last_sync_at}
                            type="info"
                        />
                    )}
                </div>
            </div>
        </div>
    );
}

function TimelineEvent({ label, time, type }: { label: string; time: string; type: 'info' | 'success' | 'error' }) {
    const colors = {
        info: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        success: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        error: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    };

    return (
        <div className="flex items-center gap-3">
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium ${colors[type]}`}>
                {label}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
                {formatRelativeTime(time)}
            </span>
        </div>
    );
}
