//! Fixture-based integration tests for beecdiff library.
//!
//! These tests use production-like Kubernetes manifests stored in fixture files
//! to verify the diff algorithm works correctly on real-world scenarios.
//!
//! HTML diff output files are generated in tests/output/ directory.

use beecdiff::{
    aggregate_k8s_resources_managed_fields, aggregate_managed_fields_to_ignore,
    multi_document_parser_for_k8s_resources, Diff,
};
use std::fs;

// ==================== Fixture Loading Helpers ====================

const DEPLOYMENT_V1: &str = include_str!("fixtures/deployment_v1.yaml");
const DEPLOYMENT_V2: &str = include_str!("fixtures/deployment_v2.yaml");
const MULTI_RESOURCE_V1: &str = include_str!("fixtures/multi_resource_v1.yaml");
const MULTI_RESOURCE_V2: &str = include_str!("fixtures/multi_resource_v2.yaml");
const STATEFULSET_V1: &str = include_str!("fixtures/statefulset_v1.yaml");
const STATEFULSET_V2: &str = include_str!("fixtures/statefulset_v2.yaml");
const MINIMAL_DEPLOYMENT: &str = include_str!("fixtures/minimal_deployment.yaml");
const IDENTICAL_DEPLOYMENT: &str = include_str!("fixtures/identical_deployment.yaml");
const WITH_MANAGED_FIELDS_V1: &str = include_str!("fixtures/with_managed_fields_v1.yaml");
const WITH_MANAGED_FIELDS_V2: &str = include_str!("fixtures/with_managed_fields_v2.yaml");

/// Parse a single YAML document into JSON
fn parse_yaml(yaml: &str) -> serde_json::Value {
    serde_yaml::from_str(yaml).expect("Failed to parse YAML fixture")
}

/// Create a diff between two YAML strings
fn diff_yamls(lhs: &str, rhs: &str) -> Diff {
    Diff::new(Some(parse_yaml(lhs)), Some(parse_yaml(rhs)), None, None)
}

// ==================== HTML Output Generation ====================

mod html_output {
    use super::*;

    const OUTPUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/output");

    /// Ensures the output directory exists
    fn ensure_output_dir() {
        fs::create_dir_all(OUTPUT_DIR).expect("Failed to create output directory");
    }

    /// Escapes HTML special characters
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    /// Converts ANSI-colored diff output to HTML with CSS styling
    fn diff_text_to_html(diff_text: &str) -> String {
        let mut html_lines = Vec::new();

        for line in diff_text.lines() {
            // The diff format is:
            // - Added:    "\x1b[32m+ content\x1b[0m"
            // - Removed:  "\x1b[31m- content\x1b[0m"
            // - Updated:  "\x1b[32m+ content\x1b[0m"
            // - NoChange: "\x1b[0m  content\x1b[0m"
            //
            // The first non-ANSI character is the diff marker (+, -, or space)

            let (class, display_line) = if line.starts_with("\x1b[32m+") {
                // Added or Updated (green +)
                let content = line
                    .trim_start_matches("\x1b[32m")
                    .trim_end_matches("\x1b[0m");
                ("added", format!("+{}", escape_html(&content[1..])))
            } else if line.starts_with("\x1b[31m-") {
                // Removed (red -)
                let content = line
                    .trim_start_matches("\x1b[31m")
                    .trim_end_matches("\x1b[0m");
                ("removed", format!("-{}", escape_html(&content[1..])))
            } else if line.starts_with("\x1b[0m ") {
                // NoChange (space)
                let content = line
                    .trim_start_matches("\x1b[0m")
                    .trim_end_matches("\x1b[0m");
                ("unchanged", escape_html(content))
            } else {
                // Fallback for lines without ANSI codes
                ("unchanged", escape_html(line))
            };

            html_lines.push(format!(
                r#"<div class="line {}"><pre>{}</pre></div>"#,
                class, display_line
            ));
        }

        html_lines.join("\n")
    }

    /// Generates a complete HTML document with diff visualization
    fn generate_html(
        test_name: &str,
        lhs_yaml: &str,
        rhs_yaml: &str,
        diff: &Diff,
        ordered_changes: &[String],
    ) -> String {
        let diff_text = diff.text(false);
        let diff_html = diff_text_to_html(&diff_text);

        format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diff: {test_name}</title>
    <style>
        :root {{
            --bg-color: #1e1e1e;
            --text-color: #d4d4d4;
            --added-bg: #1e3a1e;
            --added-text: #4ec94e;
            --removed-bg: #3a1e1e;
            --removed-text: #ec4e4e;
            --border-color: #3c3c3c;
            --header-bg: #2d2d2d;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }}
        h1, h2, h3 {{ color: #fff; margin-bottom: 15px; }}
        h1 {{ border-bottom: 2px solid var(--border-color); padding-bottom: 10px; }}
        .container {{ max-width: 1800px; margin: 0 auto; }}
        .section {{
            background: var(--header-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }}
        .columns {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        .diff-view {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }}
        .line {{
            padding: 2px 10px;
            border-radius: 2px;
            margin: 1px 0;
        }}
        .line pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .line.added {{
            background-color: var(--added-bg);
            color: var(--added-text);
        }}
        .line.removed {{
            background-color: var(--removed-bg);
            color: var(--removed-text);
        }}
        .line.unchanged {{
            color: var(--text-color);
            opacity: 0.7;
        }}
        .yaml-view {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            background: #252526;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 500px;
            overflow-y: auto;
        }}
        .changes-list {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            background: #252526;
            padding: 15px;
            border-radius: 4px;
            max-height: 300px;
            overflow-y: auto;
        }}
        .changes-list li {{
            padding: 3px 0;
            list-style: none;
        }}
        .changes-list li.add {{ color: var(--added-text); }}
        .changes-list li.remove {{ color: var(--removed-text); }}
        .changes-list li.update {{ color: #e0e040; }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }}
        .stat {{
            padding: 10px 20px;
            background: #252526;
            border-radius: 4px;
        }}
        .stat.additions {{ border-left: 4px solid var(--added-text); }}
        .stat.deletions {{ border-left: 4px solid var(--removed-text); }}
        .stat.total {{ border-left: 4px solid #4e9fec; }}
        .timestamp {{
            color: #888;
            font-size: 12px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Diff Report: {test_name}</h1>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <div class="stats">
                <div class="stat additions">
                    <strong>Additions:</strong> {additions}
                </div>
                <div class="stat deletions">
                    <strong>Deletions:</strong> {deletions}
                </div>
                <div class="stat total">
                    <strong>Total Changes:</strong> {total}
                </div>
            </div>
        </div>

        <div class="section">
            <h2>📝 Diff Output</h2>
            <div class="diff-view">
                {diff_html}
            </div>
        </div>

        <div class="section">
            <h2>📋 Ordered Changes</h2>
            <ul class="changes-list">
                {changes_html}
            </ul>
        </div>

        <div class="section">
            <h2>📄 Source Documents</h2>
            <div class="columns">
                <div>
                    <h3>Left (Original)</h3>
                    <div class="yaml-view">{lhs_escaped}</div>
                </div>
                <div>
                    <h3>Right (Updated)</h3>
                    <div class="yaml-view">{rhs_escaped}</div>
                </div>
            </div>
        </div>

        <p class="timestamp">Generated by beecdiff fixture tests</p>
    </div>
</body>
</html>"##,
            test_name = test_name,
            diff_html = diff_html,
            additions = ordered_changes
                .iter()
                .filter(|c| c.starts_with('+'))
                .count(),
            deletions = ordered_changes
                .iter()
                .filter(|c| c.starts_with('-'))
                .count(),
            total = ordered_changes.len(),
            changes_html = ordered_changes
                .iter()
                .map(|c| {
                    let class = if c.starts_with('+') {
                        "add"
                    } else if c.starts_with('-') {
                        "remove"
                    } else if c.starts_with('^') {
                        "update"
                    } else {
                        ""
                    };
                    format!(r#"<li class="{}">{}</li>"#, class, escape_html(c))
                })
                .collect::<Vec<_>>()
                .join("\n                "),
            lhs_escaped = escape_html(lhs_yaml),
            rhs_escaped = escape_html(rhs_yaml),
        )
    }

    /// Writes an HTML diff report to the output directory
    pub fn write_diff_report(test_name: &str, lhs_yaml: &str, rhs_yaml: &str, diff: &Diff) {
        ensure_output_dir();

        let ordered_changes = diff.ordered_changes();
        let html = generate_html(test_name, lhs_yaml, rhs_yaml, diff, &ordered_changes);

        let filename = format!("{}/{}.html", OUTPUT_DIR, test_name);
        fs::write(&filename, html).expect("Failed to write HTML report");

        println!("📄 HTML diff report written to: {}", filename);
    }
}

// ==================== Large Deployment Diff Tests ====================

mod deployment_tests {
    use super::*;

    #[test]
    fn test_major_version_upgrade_detects_all_changes() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Should detect changes between v1 and v2");

        let changes = diff.ordered_changes();

        // Version label changes
        assert!(
            changes.iter().any(|c| c.contains("version")),
            "Should detect version label change"
        );

        // Replica count change (5 -> 8)
        assert!(
            changes.iter().any(|c| c.contains("replicas")),
            "Should detect replicas change"
        );

        // Image version change
        assert!(
            changes.iter().any(|c| c.contains("image")),
            "Should detect image change"
        );

        // New environment variables added
        assert!(
            changes.iter().any(|c| c.starts_with('+')),
            "Should detect additions"
        );
    }

    #[test]
    fn test_deployment_diff_text_output() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let text_output = diff.text(false);
        assert!(!text_output.is_empty(), "Text output should not be empty");

        // Should contain ANSI color codes for changes
        assert!(
            text_output.contains("\x1b[32m") || text_output.contains("\x1b[31m"),
            "Should contain color codes"
        );
    }

    #[test]
    fn test_deployment_diff_manifest_mode() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let manifest_output = diff.text(true);
        assert!(
            !manifest_output.is_empty(),
            "Manifest output should not be empty"
        );

        // Manifest mode should NOT contain ANSI codes
        assert!(
            !manifest_output.contains("\x1b[31m"),
            "Manifest mode should not have red ANSI codes"
        );
    }

    #[test]
    fn test_deployment_resource_changes() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // Resource requests/limits changed (500m/512Mi -> 1000m/1Gi)
        assert!(
            changes
                .iter()
                .any(|c| c.contains("cpu") || c.contains("memory")),
            "Should detect resource changes"
        );
    }

    #[test]
    fn test_deployment_security_context_additions() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // v2 adds seccompProfile and container securityContext
        assert!(
            changes
                .iter()
                .any(|c| c.starts_with('+') && c.contains("security")),
            "Should detect security context additions"
        );
    }

    #[test]
    fn test_deployment_affinity_changes() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // Affinity changed from preferred to required
        assert!(
            changes.iter().any(|c| c.contains("affinity")),
            "Should detect affinity changes"
        );
    }
}

// ==================== Multi-Resource Document Tests ====================

mod multi_resource_tests {
    use super::*;

    #[test]
    fn test_parse_multi_resource_documents() {
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        assert_eq!(docs_v1.len(), 4, "V1 should have 4 resources");
        assert_eq!(docs_v2.len(), 4, "V2 should have 4 resources");
    }

    #[test]
    fn test_multi_resource_individual_diffs() {
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        let mut changed_resources = Vec::new();

        for (key, lhs_doc) in &docs_v1 {
            if let Some(rhs_doc) = docs_v2.get(key) {
                let mut diff = Diff::new(Some(lhs_doc.clone()), Some(rhs_doc.clone()), None, None);
                diff.do_compare().unwrap();

                if diff.is_diff() {
                    changed_resources.push(key.clone());
                }
            }
        }

        // All 4 resources should have changes
        assert_eq!(
            changed_resources.len(),
            4,
            "All resources should have changes: {:?}",
            changed_resources
        );
    }

    #[test]
    fn test_configmap_nginx_config_change() {
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        // Find nginx-config
        let nginx_key = docs_v1
            .keys()
            .find(|k| k.contains("nginx-config"))
            .expect("Should find nginx-config");

        let lhs = docs_v1.get(nginx_key).unwrap();
        let rhs = docs_v2.get(nginx_key).unwrap();

        let mut diff = Diff::new(Some(lhs.clone()), Some(rhs.clone()), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Nginx config should have changes");
    }

    #[test]
    fn test_service_port_additions() {
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        // Find backend-service
        let svc_key = docs_v1
            .keys()
            .find(|k| k.contains("backend-service"))
            .expect("Should find backend-service");

        let lhs = docs_v1.get(svc_key).unwrap();
        let rhs = docs_v2.get(svc_key).unwrap();

        let mut diff = Diff::new(Some(lhs.clone()), Some(rhs.clone()), None, None);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // v2 adds grpc port
        assert!(
            changes.iter().any(|c| c.starts_with('+')),
            "Should detect port additions"
        );
    }
}

// ==================== StatefulSet Tests ====================

mod statefulset_tests {
    use super::*;

    #[test]
    fn test_statefulset_major_upgrade() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        assert!(
            diff.is_diff(),
            "Should detect StatefulSet changes between versions"
        );
    }

    #[test]
    fn test_statefulset_postgres_version_upgrade() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // PostgreSQL version label (15.2 -> 16.1)
        assert!(
            changes.iter().any(|c| c.contains("version")),
            "Should detect version change"
        );

        // Image change
        assert!(
            changes.iter().any(|c| c.contains("image")),
            "Should detect image change"
        );
    }

    #[test]
    fn test_statefulset_new_container_added() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // v2 adds pgbouncer sidecar
        assert!(
            changes.iter().any(|c| c.starts_with('+')),
            "Should detect new container additions"
        );
    }

    #[test]
    fn test_statefulset_tls_enabled() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();
        let text = diff.text(false).to_lowercase();

        // TLS configuration added - check both changes list and text output
        let has_tls_change = changes.iter().any(|c| {
            let lower = c.to_lowercase();
            lower.contains("tls") || lower.contains("cert") || lower.contains("enable_tls")
        }) || text.contains("tls")
            || text.contains("cert");

        assert!(
            has_tls_change,
            "Should detect TLS configuration changes. Changes: {:?}",
            changes
        );
    }

    #[test]
    fn test_statefulset_storage_increase() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // Storage increased from 100Gi to 200Gi
        assert!(
            changes.iter().any(|c| c.contains("storage")),
            "Should detect storage change"
        );
    }

    #[test]
    fn test_statefulset_pod_management_policy_change() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // podManagementPolicy changed from OrderedReady to Parallel
        assert!(
            changes.iter().any(|c| c.contains("podManagementPolicy")),
            "Should detect podManagementPolicy change"
        );
    }
}

// ==================== Identity/No-Change Tests ====================

mod identity_tests {
    use super::*;

    #[test]
    fn test_identical_documents_no_diff() {
        let mut diff = diff_yamls(MINIMAL_DEPLOYMENT, IDENTICAL_DEPLOYMENT);
        diff.do_compare().unwrap();

        assert!(
            !diff.is_diff(),
            "Identical documents should have no differences"
        );

        let changes = diff.ordered_changes();
        assert!(
            changes.is_empty(),
            "Should have no changes for identical docs"
        );
    }

    #[test]
    fn test_self_diff_no_changes() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V1);
        diff.do_compare().unwrap();

        assert!(
            !diff.is_diff(),
            "Diffing document against itself should show no changes"
        );
    }

    #[test]
    fn test_statefulset_self_diff() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V1);
        diff.do_compare().unwrap();

        assert!(
            !diff.is_diff(),
            "StatefulSet self-diff should show no changes"
        );
    }
}

// ==================== Managed Fields Tests ====================

mod managed_fields_tests {
    use super::*;

    #[test]
    fn test_parse_managed_fields() {
        let result =
            aggregate_k8s_resources_managed_fields(None, Some(&WITH_MANAGED_FIELDS_V1.to_string()));

        assert!(result.is_ok(), "Should parse managed fields");
        let field_sets = result.unwrap();
        assert!(!field_sets.is_empty(), "Should have field sets");
    }

    #[test]
    fn test_ignore_kube_controller_manager_fields() {
        let result = aggregate_managed_fields_to_ignore(
            None,
            Some(&WITH_MANAGED_FIELDS_V1.to_string()),
            Some(String::from("kube-controller-manager")),
        );

        assert!(result.is_ok(), "Should create ignore sets");
        let ignore_sets = result.unwrap();
        assert!(
            !ignore_sets.is_empty(),
            "Should have ignore sets for kube-controller-manager"
        );
    }

    #[test]
    fn test_ignore_karpenter_annotations() {
        let result = aggregate_managed_fields_to_ignore(
            None,
            Some(&WITH_MANAGED_FIELDS_V1.to_string()),
            Some(String::from("karpenter")),
        );

        assert!(result.is_ok(), "Should create ignore sets for karpenter");
    }

    #[test]
    fn test_diff_with_multiple_ignored_managers() {
        let lhs_str = WITH_MANAGED_FIELDS_V1.to_string();
        let rhs_str = WITH_MANAGED_FIELDS_V2.to_string();

        // Get ignore sets for system managers
        let ignore_sets = aggregate_managed_fields_to_ignore(
            None,
            Some(&lhs_str),
            Some(String::from("kube-controller-manager,karpenter")),
        )
        .unwrap_or_default();

        let docs_v1 = multi_document_parser_for_k8s_resources(None, Some(&lhs_str)).unwrap();
        let docs_v2 = multi_document_parser_for_k8s_resources(None, Some(&rhs_str)).unwrap();

        for (key, lhs_doc) in &docs_v1 {
            if let Some(rhs_doc) = docs_v2.get(key) {
                let ignore_set = ignore_sets.get(key).cloned().flatten();

                let mut diff = Diff::new(
                    Some(lhs_doc.clone()),
                    Some(rhs_doc.clone()),
                    None,
                    ignore_set,
                );
                diff.do_compare().unwrap();

                // Should still detect user-managed changes
                assert!(diff.is_diff(), "Should detect user changes");

                let changes = diff.ordered_changes();

                // Should NOT contain status changes (managed by kube-controller-manager)
                let has_status_change = changes
                    .iter()
                    .any(|c| c.contains("availableReplicas") || c.contains("readyReplicas"));
                assert!(
                    !has_status_change,
                    "Status fields should be ignored: {:?}",
                    changes
                );
            }
        }
    }

    #[test]
    fn test_diff_detects_user_managed_changes() {
        let lhs_str = WITH_MANAGED_FIELDS_V1.to_string();
        let rhs_str = WITH_MANAGED_FIELDS_V2.to_string();

        let field_sets =
            aggregate_k8s_resources_managed_fields(None, Some(&lhs_str)).unwrap_or_default();

        let docs_v1 = multi_document_parser_for_k8s_resources(None, Some(&lhs_str)).unwrap();
        let docs_v2 = multi_document_parser_for_k8s_resources(None, Some(&rhs_str)).unwrap();

        for (key, lhs_doc) in &docs_v1 {
            if let Some(rhs_doc) = docs_v2.get(key) {
                let field_set = field_sets.get(key).cloned().flatten();

                let mut diff = Diff::new(
                    Some(lhs_doc.clone()),
                    Some(rhs_doc.clone()),
                    field_set,
                    None,
                );
                diff.do_compare().unwrap();

                let changes = diff.ordered_changes();

                // Should detect version, image, replicas changes
                assert!(
                    changes.iter().any(|c| c.contains("version")
                        || c.contains("image")
                        || c.contains("replicas")),
                    "Should detect user-managed changes"
                );
            }
        }
    }
}

// ==================== Output Quality Tests ====================

mod output_tests {
    use super::*;

    #[test]
    fn test_large_diff_ordered_changes_not_empty() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();
        assert!(
            changes.len() > 5,
            "Large diff should have many changes, got: {}",
            changes.len()
        );
    }

    #[test]
    fn test_ordered_changes_prefixes_valid() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();
        for change in &changes {
            let prefix = change.chars().next().unwrap();
            assert!(
                prefix == '+' || prefix == '-' || prefix == '^',
                "Invalid prefix in change: {}",
                change
            );
        }
    }

    #[test]
    fn test_text_output_has_proper_indentation() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let text = diff.text(true);
        let lines: Vec<&str> = text.lines().collect();

        // Should have multiple indentation levels
        let has_base_indent = lines.iter().any(|l| l.starts_with("  "));
        let has_nested_indent = lines.iter().any(|l| l.starts_with("    "));

        assert!(has_base_indent, "Should have base indentation");
        assert!(has_nested_indent, "Should have nested indentation");
    }

    #[test]
    fn test_remove_childrenless_parents() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();
        diff.remove_childrenless_parents();

        // Should still have diff after cleanup
        assert!(diff.is_diff(), "Should still have diff after cleanup");
    }

    #[test]
    fn test_multi_resource_aggregate_changes() {
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        let mut total_changes = 0;

        for (key, lhs_doc) in &docs_v1 {
            if let Some(rhs_doc) = docs_v2.get(key) {
                let mut diff = Diff::new(Some(lhs_doc.clone()), Some(rhs_doc.clone()), None, None);
                diff.do_compare().unwrap();
                total_changes += diff.ordered_changes().len();
            }
        }

        assert!(
            total_changes > 20,
            "Multi-resource diff should have many total changes: {}",
            total_changes
        );
    }
}

// ==================== Edge Cases and Robustness Tests ====================

mod robustness_tests {
    use super::*;

    #[test]
    fn test_large_text_field_diff() {
        // nginx.conf is a large text field
        let docs_v1 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .expect("Should parse v1");
        let docs_v2 =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .expect("Should parse v2");

        let nginx_key = docs_v1
            .keys()
            .find(|k| k.contains("nginx-config"))
            .expect("Should find nginx-config");

        let lhs = docs_v1.get(nginx_key).unwrap();
        let rhs = docs_v2.get(nginx_key).unwrap();

        let mut diff = Diff::new(Some(lhs.clone()), Some(rhs.clone()), None, None);

        // Should not panic on large text fields
        let result = diff.do_compare();
        assert!(result.is_ok(), "Should handle large text fields");
    }

    #[test]
    fn test_deeply_nested_statefulset() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);

        // Should handle complex nested structures without issues
        let result = diff.do_compare();
        assert!(result.is_ok(), "Should handle deeply nested structures");
    }

    #[test]
    fn test_multiple_containers_diff() {
        // deployment_v1 has 2 containers, v2 has 2 containers with changes
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // Should detect envoy image change
        let has_envoy_change = changes
            .iter()
            .any(|c| c.contains("envoy") || c.contains("1.28"));
        assert!(
            has_envoy_change || changes.len() > 10,
            "Should detect changes in multiple containers"
        );
    }

    #[test]
    fn test_volume_changes() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();

        // v2 adds tmp-volume
        assert!(
            changes
                .iter()
                .any(|c| c.contains("volume") || c.contains("tmp")),
            "Should detect volume changes"
        );
    }

    #[test]
    fn test_diff_consistency_multiple_runs() {
        let lhs = parse_yaml(DEPLOYMENT_V1);
        let rhs = parse_yaml(DEPLOYMENT_V2);

        let mut results = Vec::new();

        for _ in 0..5 {
            let mut diff = Diff::new(Some(lhs.clone()), Some(rhs.clone()), None, None);
            diff.do_compare().unwrap();
            results.push(diff.ordered_changes().len());
        }

        // All runs should produce the same number of changes
        let first = results[0];
        assert!(
            results.iter().all(|&r| r == first),
            "Diff should be deterministic: {:?}",
            results
        );
    }
}

// ==================== HTML Report Generation Tests ====================

mod html_report_tests {
    use super::*;

    #[test]
    fn generate_deployment_diff_report() {
        let mut diff = diff_yamls(DEPLOYMENT_V1, DEPLOYMENT_V2);
        diff.do_compare().unwrap();
        html_output::write_diff_report("deployment_v1_to_v2", DEPLOYMENT_V1, DEPLOYMENT_V2, &diff);
    }

    #[test]
    fn generate_statefulset_diff_report() {
        let mut diff = diff_yamls(STATEFULSET_V1, STATEFULSET_V2);
        diff.do_compare().unwrap();
        html_output::write_diff_report(
            "statefulset_v1_to_v2",
            STATEFULSET_V1,
            STATEFULSET_V2,
            &diff,
        );
    }

    #[test]
    fn generate_multi_resource_diff_report() {
        // Parse multi-document files and diff each resource
        let lhs_docs =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V1.to_string()))
                .unwrap();
        let rhs_docs =
            multi_document_parser_for_k8s_resources(None, Some(&MULTI_RESOURCE_V2.to_string()))
                .unwrap();

        for (key, lhs_value) in &lhs_docs {
            if let Some(rhs_value) = rhs_docs.get(key) {
                let mut diff =
                    Diff::new(Some(lhs_value.clone()), Some(rhs_value.clone()), None, None);
                diff.do_compare().unwrap();

                // Sanitize key for filename: replace problematic characters
                let safe_key = key.replace(", ", "_").replace(' ', "_").replace('/', "_");
                let lhs_yaml = serde_yaml::to_string(lhs_value).unwrap();
                let rhs_yaml = serde_yaml::to_string(rhs_value).unwrap();
                html_output::write_diff_report(
                    &format!("multi_resource_{}", safe_key),
                    &lhs_yaml,
                    &rhs_yaml,
                    &diff,
                );
            }
        }
    }

    #[test]
    fn generate_minimal_to_full_diff_report() {
        let mut diff = diff_yamls(MINIMAL_DEPLOYMENT, DEPLOYMENT_V2);
        diff.do_compare().unwrap();
        html_output::write_diff_report(
            "minimal_to_full_deployment",
            MINIMAL_DEPLOYMENT,
            DEPLOYMENT_V2,
            &diff,
        );
    }

    #[test]
    fn generate_identical_diff_report() {
        let mut diff = diff_yamls(IDENTICAL_DEPLOYMENT, IDENTICAL_DEPLOYMENT);
        diff.do_compare().unwrap();
        html_output::write_diff_report(
            "identical_no_changes",
            IDENTICAL_DEPLOYMENT,
            IDENTICAL_DEPLOYMENT,
            &diff,
        );
    }

    #[test]
    fn generate_managed_fields_diff_report() {
        // This shows how managed fields filtering affects the diff
        let lhs = parse_yaml(WITH_MANAGED_FIELDS_V1);
        let rhs = parse_yaml(WITH_MANAGED_FIELDS_V2);

        // Get managed fields from the "live" document
        let managed_fields =
            aggregate_k8s_resources_managed_fields(None, Some(&WITH_MANAGED_FIELDS_V1.to_string()))
                .unwrap();

        // Find the field set for this resource
        let field_set = managed_fields.values().next().and_then(|v| v.clone());

        let mut diff = Diff::new(Some(lhs), Some(rhs), field_set, None);
        diff.do_compare().unwrap();
        html_output::write_diff_report(
            "with_managed_fields_filtering",
            WITH_MANAGED_FIELDS_V1,
            WITH_MANAGED_FIELDS_V2,
            &diff,
        );
    }
}
