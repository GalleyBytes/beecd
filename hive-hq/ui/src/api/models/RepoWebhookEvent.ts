/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Webhook event record (for audit log)
 */
export type RepoWebhookEvent = {
    after_sha?: string | null;
    before_sha?: string | null;
    created_at: string;
    delivery_id: string;
    event_type: string;
    id: string;
    matched_paths?: any[] | null;
    processed_at?: string | null;
    processing_error?: string | null;
    pusher?: string | null;
    ref_name?: string | null;
    updated_service_versions?: any[] | null;
    webhook_id: string;
};

