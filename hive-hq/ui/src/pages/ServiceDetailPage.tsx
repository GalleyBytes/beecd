import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, RefreshCw, ExternalLink, GitBranch, Package, Check, History, Plus, AlertTriangle, Trash2, Clock, FileCode, Webhook, CheckCircle, AlertCircle } from 'lucide-react';
import { PageHeader, Alert } from '@/components';
import { useServiceDefinition, useServiceDefinitionVersions, useCreateServiceVersion, useDeprecateServiceVersion, useDeleteServiceVersion, useUpdateManifestPathTemplate, useValidatePathTemplate } from '@/hooks';
import type { CreateServiceVersion } from '@/types';

const GITHUB_URL = 'https://github.com';

export function ServiceDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    const [showAddVersionModal, setShowAddVersionModal] = useState(false);

    // Manifest path template state
    const [editingPathTemplate, setEditingPathTemplate] = useState(false);
    const [pathTemplateInput, setPathTemplateInput] = useState('');
    const [pathTemplateError, setPathTemplateError] = useState<string | null>(null);

    // New version form state
    const [newVersionForm, setNewVersionForm] = useState<Partial<CreateServiceVersion>>({
        version: '',
        path: '',
        hash: '',
        git_sha: '',
        source: '',
        namespace_id: '',
    });

    const { data: service, isLoading, isError, error, refetch } = useServiceDefinition(id!);

    // Service versions
    const { data: serviceVersions = [], isLoading: isLoadingVersions, refetch: refetchVersions } = useServiceDefinitionVersions(id!);
    const createVersionMutation = useCreateServiceVersion();
    const deprecateVersionMutation = useDeprecateServiceVersion();
    const deleteVersionMutation = useDeleteServiceVersion();

    // Manifest path template
    const updatePathTemplateMutation = useUpdateManifestPathTemplate();
    const validatePathTemplateMutation = useValidatePathTemplate();

    const resetVersionForm = () => {
        setNewVersionForm({
            version: '',
            path: '',
            hash: '',
            git_sha: '',
            source: '',
            namespace_id: '',
        });
    };

    const handleCreateVersion = async () => {
        if (!id || !newVersionForm.version || !newVersionForm.path || !newVersionForm.hash || !newVersionForm.git_sha || !newVersionForm.namespace_id) return;

        try {
            await createVersionMutation.mutateAsync({
                service_definition_id: id,
                version: newVersionForm.version,
                path: newVersionForm.path,
                hash: newVersionForm.hash,
                git_sha: newVersionForm.git_sha,
                source: newVersionForm.source || 'api',
                namespace_id: newVersionForm.namespace_id,
            });
            setShowAddVersionModal(false);
            resetVersionForm();
            refetchVersions();
        } catch (err) {
            console.error('Failed to create version:', err);
        }
    };

    const handleDeprecateVersion = async (versionId: string) => {
        try {
            await deprecateVersionMutation.mutateAsync({ id: versionId });
            refetchVersions();
        } catch (err) {
            console.error('Failed to deprecate version:', err);
        }
    };

    const handleDeleteVersion = async (versionId: string) => {
        if (!confirm('Are you sure you want to delete this version?')) return;
        try {
            await deleteVersionMutation.mutateAsync(versionId);
            refetchVersions();
        } catch (err) {
            console.error('Failed to delete version:', err);
        }
    };

    const startEditingPathTemplate = () => {
        setPathTemplateInput(service?.manifest_path_template || '');
        setPathTemplateError(null);
        setEditingPathTemplate(true);
    };

    const cancelEditingPathTemplate = () => {
        setEditingPathTemplate(false);
        setPathTemplateError(null);
    };

    const validateAndSavePathTemplate = async () => {
        if (!id || !pathTemplateInput.trim()) return;

        try {
            // First validate the template
            const validation = await validatePathTemplateMutation.mutateAsync(pathTemplateInput.trim());

            if (!validation.valid) {
                setPathTemplateError(validation.error || 'Invalid template');
                return;
            }

            // Then save it
            await updatePathTemplateMutation.mutateAsync({
                serviceDefinitionId: id,
                manifestPathTemplate: pathTemplateInput.trim()
            });

            setEditingPathTemplate(false);
            setPathTemplateError(null);
            refetch();
        } catch (err) {
            setPathTemplateError(err instanceof Error ? err.message : 'Failed to update template');
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
                <span className="ml-3 text-gray-600 dark:text-gray-400">Loading service definition...</span>
            </div>
        );
    }

    if (isError || !service) {
        return (
            <div className="p-4">
                <Alert
                    type="error"
                    title="Failed to load service definition"
                    message={error instanceof Error ? error.message : 'Service definition not found'}
                />
                <button
                    onClick={() => navigate('/services')}
                    className="mt-4 inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to Services
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate(`/services/name/${service.name}`)}
                    className="inline-flex items-center text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100"
                >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    Back to {service.name}
                </button>
                <button
                    onClick={() => refetch()}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                </button>
            </div>

            <PageHeader
                title={service.name}
                description={`Service definition: ${service.org}/${service.repo}@${service.branch}`}
            />

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <Package className="w-8 h-8 text-blue-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Repository</p>
                            <a
                                href={`${GITHUB_URL}/${service.org}/${service.repo}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-lg font-semibold text-gray-900 dark:text-gray-100 hover:text-blue-600 dark:hover:text-blue-400 inline-flex items-center"
                            >
                                {service.org}/{service.repo}
                                <ExternalLink className="w-4 h-4 ml-1" />
                            </a>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <GitBranch className="w-8 h-8 text-green-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Branch</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{service.branch}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
                    <div className="flex items-center">
                        <History className="w-8 h-8 text-purple-500" />
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Versions</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                                {serviceVersions.filter(v => !v.deprecated_at).length}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Service Details */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">Service Details</h3>
                </div>
                <div className="px-4 py-5 sm:px-6">
                    <dl className="divide-y divide-gray-200 dark:divide-gray-700">
                        <InfoRow label="Service Name" value={service.name} />
                        <InfoRow
                            label="Repository"
                            value={`${service.org}/${service.repo}`}
                            link={`/repos/${service.repo_id}`}
                        />
                        <InfoRow label="Branch" value={service.branch} />
                        <InfoRow
                            label="Source Branch Requirements"
                            value={service.source_branch_requirements || 'None'}
                        />
                        <InfoRow
                            label="Service Definition ID"
                            value={<span className="font-mono text-xs">{service.service_definition_id}</span>}
                        />
                        <InfoRow
                            label="Repo Branch ID"
                            value={<span className="font-mono text-xs">{service.repo_branch_id}</span>}
                        />
                    </dl>
                </div>
            </div>

            {/* Manifest Path Template */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <FileCode className="w-5 h-5 text-purple-500" />
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">Manifest Path Template</h3>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                Configure the path pattern for automatic version detection via GitHub webhooks
                            </p>
                        </div>
                    </div>
                    {!editingPathTemplate && (
                        <button
                            onClick={startEditingPathTemplate}
                            className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                        >
                            {service.manifest_path_template ? 'Edit' : 'Configure'}
                        </button>
                    )}
                </div>
                <div className="px-4 py-5 sm:px-6">
                    {editingPathTemplate ? (
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                    Path Template
                                </label>
                                <input
                                    type="text"
                                    value={pathTemplateInput}
                                    onChange={(e) => {
                                        setPathTemplateInput(e.target.value);
                                        setPathTemplateError(null);
                                    }}
                                    placeholder="manifests/{cluster}/{namespace}/{service}"
                                    className={`w-full px-3 py-2 border rounded-md font-mono text-sm bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 ${pathTemplateError
                                        ? 'border-red-500 focus:ring-red-500 focus:border-red-500'
                                        : 'border-gray-300 dark:border-gray-600 focus:ring-blue-500 focus:border-blue-500'
                                        }`}
                                />
                                {pathTemplateError && (
                                    <p className="mt-1 text-sm text-red-600 dark:text-red-400 flex items-center">
                                        <AlertCircle className="w-4 h-4 mr-1" />
                                        {pathTemplateError}
                                    </p>
                                )}
                            </div>
                            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-md p-3">
                                <p className="text-xs text-blue-800 dark:text-blue-200 font-medium mb-2">Required Placeholders:</p>
                                <div className="flex flex-wrap gap-2">
                                    <code className="text-xs bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-100 px-2 py-0.5 rounded">{'{service}'}</code>
                                    <code className="text-xs bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-100 px-2 py-0.5 rounded">{'{cluster}'}</code>
                                    <code className="text-xs bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-100 px-2 py-0.5 rounded">{'{namespace}'}</code>
                                </div>
                                <p className="text-xs text-blue-700 dark:text-blue-300 mt-2">
                                    When files matching this pattern are pushed to GitHub, service versions will be automatically created.
                                </p>
                            </div>
                            <div className="flex justify-end gap-2">
                                <button
                                    onClick={cancelEditingPathTemplate}
                                    className="px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={validateAndSavePathTemplate}
                                    disabled={updatePathTemplateMutation.isPending || validatePathTemplateMutation.isPending || !pathTemplateInput.trim()}
                                    className="px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {(updatePathTemplateMutation.isPending || validatePathTemplateMutation.isPending) ? 'Saving...' : 'Save Template'}
                                </button>
                            </div>
                        </div>
                    ) : service.manifest_path_template ? (
                        <div className="space-y-3">
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-5 h-5 text-green-500" />
                                <span className="text-sm text-gray-600 dark:text-gray-400">Automatic versioning configured</span>
                            </div>
                            <div>
                                <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Template:</span>
                                <code className="ml-2 text-sm font-mono bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 px-2 py-1 rounded">
                                    {service.manifest_path_template}
                                </code>
                            </div>
                            <div className="flex items-start gap-2 mt-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-md">
                                <Webhook className="w-4 h-4 text-green-600 dark:text-green-400 mt-0.5" />
                                <div>
                                    <p className="text-sm text-green-800 dark:text-green-200">
                                        When files matching this pattern are pushed to <span className="font-medium">{service.org}/{service.repo}</span> on branch <span className="font-medium">{service.branch}</span>, new service versions will be created automatically.
                                    </p>
                                    <p className="text-xs text-green-700 dark:text-green-300 mt-1">
                                        Ensure a webhook is registered for this repository. <Link to={`/repos/${service.repo_id}`} className="underline">Manage webhooks →</Link>
                                    </p>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="text-center py-4">
                            <FileCode className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-600 mb-2" />
                            <p className="text-gray-500 dark:text-gray-400">No path template configured</p>
                            <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
                                Configure a manifest path template to enable automatic version creation from GitHub pushes.
                            </p>
                        </div>
                    )}
                </div>
            </div>

            {/* Service Versions */}
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <History className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">Service Versions</h3>
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                            ({serviceVersions.filter(v => !v.deprecated_at).length} active)
                        </span>
                    </div>
                    <button
                        onClick={() => setShowAddVersionModal(true)}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                        <Plus className="w-4 h-4 mr-1" />
                        Add Version
                    </button>
                </div>

                {isLoadingVersions ? (
                    <div className="flex items-center justify-center p-8">
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                        <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">Loading versions...</span>
                    </div>
                ) : serviceVersions.length === 0 ? (
                    <div className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                        <History className="w-12 h-12 mx-auto text-gray-300 dark:text-gray-600 mb-2" />
                        <p>No versions registered</p>
                        <p className="text-sm mt-1">Add a version manually or register versions via the API from your CI/CD pipeline.</p>
                        <div className="mt-4 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-md text-left">
                            <p className="text-xs font-medium text-gray-600 dark:text-gray-300 mb-2">API Example (CI/CD):</p>
                            <code className="text-xs font-mono text-gray-600 dark:text-gray-400 break-all">
                                POST /api/service-versions<br />
                                {`{ "service_definition_id": "${service.service_definition_id}", "version": "1.0.0", "path": "charts/myservice", "hash": "<sha256>", "git_sha": "<commit>" }`}
                            </code>
                        </div>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-700/50">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Version</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Path</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Git SHA</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Namespace</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Created</th>
                                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {serviceVersions.map((version) => (
                                    <tr key={version.id} className={version.deprecated_at ? 'bg-gray-50 dark:bg-gray-700/30 opacity-60' : ''}>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            <span className="font-medium text-gray-900 dark:text-gray-100">{version.version}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <code className="text-xs font-mono text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded">
                                                {version.path}
                                            </code>
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            {version.git_sha ? (
                                                <a
                                                    href={`${GITHUB_URL}/${version.org}/${version.repo}/commit/${version.git_sha}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center text-xs font-mono text-blue-600 hover:text-blue-800 dark:text-blue-400"
                                                >
                                                    {version.git_sha.substring(0, 7)}
                                                    <ExternalLink className="w-3 h-3 ml-1" />
                                                </a>
                                            ) : (
                                                <span className="text-gray-400 text-xs">—</span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm">
                                            {version.namespace_name ? (
                                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                                    {version.namespace_name}
                                                </span>
                                            ) : (
                                                <span className="text-gray-400 text-xs">Global</span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            {version.deprecated_at ? (
                                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                                    Deprecated
                                                </span>
                                            ) : (
                                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                                    <Check className="w-3 h-3 mr-1" />
                                                    Active
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            {version.created_at ? (
                                                <span className="inline-flex items-center text-xs">
                                                    <Clock className="w-3 h-3 mr-1" />
                                                    {new Date(version.created_at).toLocaleDateString()}
                                                </span>
                                            ) : '—'}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-right text-sm font-medium">
                                            <div className="flex items-center justify-end gap-2">
                                                {!version.deprecated_at && (
                                                    <button
                                                        onClick={() => handleDeprecateVersion(version.id)}
                                                        disabled={deprecateVersionMutation.isPending}
                                                        className="text-yellow-600 hover:text-yellow-800 dark:text-yellow-400 dark:hover:text-yellow-300 disabled:opacity-50"
                                                        title="Deprecate version"
                                                    >
                                                        <AlertTriangle className="w-4 h-4" />
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => handleDeleteVersion(version.id)}
                                                    disabled={deleteVersionMutation.isPending}
                                                    className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 disabled:opacity-50"
                                                    title="Delete version"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Add Version Modal */}
            {showAddVersionModal && (
                <div className="fixed inset-0 z-50 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4">
                        <div className="fixed inset-0 bg-black/50" onClick={() => { setShowAddVersionModal(false); resetVersionForm(); }} />
                        <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                                Add Service Version
                            </h3>

                            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                                Register a new version for this service. In production, this is typically done automatically by your CI/CD pipeline.
                            </p>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Version <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g., 1.0.0, v2.3.1"
                                        value={newVersionForm.version || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, version: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Namespace ID <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="UUID of the target namespace"
                                        value={newVersionForm.namespace_id || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, namespace_id: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm font-mono focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">The namespace where this version can be deployed</p>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Path <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g., charts/myservice or services/myservice"
                                        value={newVersionForm.path || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, path: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Path to the service manifests in the repository</p>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Git SHA <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g., abc1234def5678..."
                                        value={newVersionForm.git_sha || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, git_sha: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm font-mono focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Full git commit SHA for traceability</p>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Hash <span className="text-red-500">*</span>
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="SHA256 hash of the manifests"
                                        value={newVersionForm.hash || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, hash: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm font-mono focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Content hash for change detection</p>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        Source
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g., ci-pipeline, manual, github-action"
                                        value={newVersionForm.source || ''}
                                        onChange={(e) => setNewVersionForm({ ...newVersionForm, source: e.target.value })}
                                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Optional: Where this version came from (defaults to 'api')</p>
                                </div>
                            </div>

                            {createVersionMutation.isError && (
                                <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                                    <p className="text-sm text-red-600 dark:text-red-400">
                                        Failed to create version: {createVersionMutation.error instanceof Error ? createVersionMutation.error.message : 'Unknown error'}
                                    </p>
                                </div>
                            )}

                            <div className="mt-6 flex justify-end gap-3">
                                <button
                                    onClick={() => { setShowAddVersionModal(false); resetVersionForm(); }}
                                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleCreateVersion}
                                    disabled={createVersionMutation.isPending || !newVersionForm.version || !newVersionForm.path || !newVersionForm.hash || !newVersionForm.git_sha || !newVersionForm.namespace_id}
                                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors"
                                >
                                    {createVersionMutation.isPending ? 'Creating...' : 'Create Version'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

// Helper component for info rows
function InfoRow({ label, value, link }: { label: string; value: React.ReactNode; link?: string }) {
    return (
        <div className="py-3 sm:grid sm:grid-cols-3 sm:gap-4">
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</dt>
            <dd className="mt-1 text-sm text-gray-900 dark:text-gray-100 sm:mt-0 sm:col-span-2">
                {link ? (
                    <Link to={link} className="text-blue-600 hover:text-blue-800 dark:text-blue-400">
                        {value}
                    </Link>
                ) : (
                    value
                )}
            </dd>
        </div>
    );
}
