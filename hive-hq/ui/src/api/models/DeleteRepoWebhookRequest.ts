/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to delete a provider webhook for a repo.
 *
 * If `github_token` is provided, the server will attempt to delete the webhook on GitHub.
 * If omitted, the webhook is only disabled/soft-deleted locally.
 */
export type DeleteRepoWebhookRequest = {
    github_token?: string | null;
};

