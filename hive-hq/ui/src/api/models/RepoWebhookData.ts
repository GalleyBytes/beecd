/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Webhook registration data for a repo.
 */
export type RepoWebhookData = {
    active: boolean;
    created_at: string;
    id: string;
    last_delivery_at?: string | null;
    last_error?: string | null;
    org: string;
    provider_webhook_id?: number | null;
    repo: string;
    repo_id: string;
    updated_at: string;
};

