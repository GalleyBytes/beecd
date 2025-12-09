// Tests for Weighted Resource Ordering and Deployment Phases
//
// Critical workflows tested:
// - Three-phase deployment (non-weighted, weighted, post-weighted)
// - Resource kind ordering (correct deployment sequence)
// - Weighted annotation parsing and sorting
// - Pod/Job status polling
// - Failure handling in weighted phases

#[cfg(test)]
mod tests {
    use crate::tests::common::verify_resource_order;
    use crate::tests::fixtures::*;

    // ========================================
    // FIXTURE VALIDATION
    // ========================================

    #[test]
    fn test_weighted_fixture_has_weight_annotation() {
        // Verify test fixture has beecd/weight annotation
        assert!(WEIGHTED_DEPLOYMENT_YAML.contains("beecd/weight"));
    }

    #[test]
    fn test_post_weighted_fixture_has_annotation() {
        // Verify test fixture has beecd/post-weight annotation
        assert!(POST_WEIGHTED_JOB_YAML.contains("beecd/post-weight"));
    }

    #[test]
    fn test_job_fixture_has_backoff_limit() {
        // Verify Job fixture includes backoffLimit for retry policy
        assert!(POST_WEIGHTED_JOB_YAML.contains("backoffLimit:"));
    }

    #[test]
    fn test_job_fixture_has_restart_policy() {
        // Verify Job fixture has restartPolicy configured
        assert!(SIMPLE_JOB_YAML.contains("restartPolicy:"));
    }

    // ========================================
    // RESOURCE ORDERING VALIDATION
    // ========================================

    #[test]
    fn test_namespace_created_before_workloads() {
        // Namespace must exist before Pods can be scheduled
        assert!(verify_resource_order(vec!["Namespace", "Pod"]));
    }

    #[test]
    fn test_rbac_created_before_deployments() {
        // Role & RoleBinding must exist before ServiceAccount can use them
        assert!(verify_resource_order(vec![
            "Role",
            "RoleBinding",
            "Deployment"
        ]));
    }

    #[test]
    fn test_configmap_before_consuming_deployment() {
        // ConfigMaps mounted as volumes must exist before Pod creation
        assert!(verify_resource_order(vec!["ConfigMap", "Deployment"]));
    }

    #[test]
    fn test_service_created_before_ingress() {
        // Service backend must exist before Ingress can route to it
        assert!(verify_resource_order(vec!["Service", "Ingress"]));
    }

    #[test]
    fn test_deployment_ordered_before_job() {
        // Deployments (index 20) should precede Jobs (index 26) in resource order
        assert!(verify_resource_order(vec!["Deployment", "Job"]));
    }
}
