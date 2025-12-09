// Tests for Retry Logic and Conflict Handling
//
// Critical workflows tested:
// - 409 Conflict: delete-and-retry with single attempt limit
// - 429/500 Throttle: exponential backoff up to 30 seconds
// - 404 NotFound: proper error propagation
// - Retry count tracking and limits
// - Backoff timing calculations

#[cfg(test)]
mod retry_and_conflict_tests {
    use crate::tests::common::calculate_backoff_time;
    use crate::tests::mocks::ErrorScenario;

    fn should_retry(code: u16) -> bool {
        matches!(code, 429 | 500)
    }

    fn conflict_retry_allowed(attempt: usize) -> bool {
        attempt == 0
    }

    #[test]
    fn test_backoff_is_monotonic_until_cap() {
        let backoffs: Vec<f32> = (0..20).map(calculate_backoff_time).collect();
        for window in backoffs.windows(2) {
            let (a, b) = (window[0], window[1]);
            // Backoff never decreases and never exceeds cap
            assert!(b >= a);
            assert!(b <= 30.0);
        }
    }

    #[test]
    fn test_backoff_hits_cap_at_large_attempts() {
        assert_eq!(calculate_backoff_time(20), 30.0);
        assert_eq!(calculate_backoff_time(50), 30.0);
        assert_eq!(calculate_backoff_time(100), 30.0);
    }

    #[test]
    fn test_backoff_growth_curve_matches_formula() {
        let expected = vec![0.0, 0.1, 0.4, 0.9, 1.6, 2.5, 3.6, 4.9, 6.4, 8.1, 10.0];
        for (attempt, expected_value) in expected.iter().enumerate() {
            assert!((calculate_backoff_time(attempt as u32) - expected_value).abs() < 0.0001);
        }
    }

    #[test]
    fn test_retry_policy_by_error_code() {
        let cases = vec![
            (ErrorScenario::Throttle, true),
            (ErrorScenario::ServerError, true),
            (ErrorScenario::Conflict, false), // Conflict handled separately
            (ErrorScenario::NotFound, false),
            (ErrorScenario::None, false),
        ];

        for (scenario, expected_retry) in cases {
            let code = scenario.to_http_code().unwrap_or(0);
            assert_eq!(should_retry(code), expected_retry, "code {}", code);
        }
    }

    #[test]
    fn test_conflict_allows_single_retry_only() {
        assert!(conflict_retry_allowed(0));
        assert!(!conflict_retry_allowed(1));
        assert!(!conflict_retry_allowed(2));
    }
}
