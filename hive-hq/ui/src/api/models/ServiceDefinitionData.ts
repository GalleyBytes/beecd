/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RepoProvider } from './RepoProvider';
export type ServiceDefinitionData = {
    branch: string;
    host: string;
    manifest_path_template?: string | null;
    name: string;
    org: string;
    provider: RepoProvider;
    repo: string;
    repo_branch_id: string;
    repo_id: string;
    service_definition_id: string;
    service_deleted_at?: string | null;
    source_branch_requirements?: string | null;
    web_base_url: string;
};

