// Unit tests for JWT authentication functionality in agent

#[cfg(test)]
mod tests {
    use crate::agent::{PublicChronoDuration as ChronoDuration, PublicUtc as Utc, TokenState};
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_token_state_fields() {
        let now = Utc::now();
        let token_state = TokenState {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            access_expires_at: now + ChronoDuration::seconds(900),
            refresh_expires_at: now + ChronoDuration::seconds(86400),
        };

        assert_eq!(token_state.access_token, "test_access_token");
        assert_eq!(token_state.refresh_token, "test_refresh_token");
        assert!(token_state.access_expires_at > now);
        assert!(token_state.refresh_expires_at > now);
        assert!(token_state.refresh_expires_at > token_state.access_expires_at);
    }

    #[test]
    fn test_token_state_shared_access() {
        let now = Utc::now();
        let token_state = Arc::new(RwLock::new(Some(TokenState {
            access_token: "initial_token".to_string(),
            refresh_token: "initial_refresh".to_string(),
            access_expires_at: now + ChronoDuration::seconds(900),
            refresh_expires_at: now + ChronoDuration::seconds(86400),
        })));

        // Test concurrent read access
        let state_clone1 = Arc::clone(&token_state);
        let state_clone2 = Arc::clone(&token_state);

        let handle1 = std::thread::spawn(move || {
            let state = state_clone1.read().unwrap();
            state.as_ref().map(|s| s.access_token.clone())
        });

        let handle2 = std::thread::spawn(move || {
            let state = state_clone2.read().unwrap();
            state.as_ref().map(|s| s.access_token.clone())
        });

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        assert_eq!(result1, Some("initial_token".to_string()));
        assert_eq!(result2, Some("initial_token".to_string()));
    }

    #[test]
    fn test_token_state_update() {
        let now = Utc::now();
        let token_state = Arc::new(RwLock::new(Some(TokenState {
            access_token: "old_token".to_string(),
            refresh_token: "old_refresh".to_string(),
            access_expires_at: now + ChronoDuration::seconds(60),
            refresh_expires_at: now + ChronoDuration::seconds(3600),
        })));

        // Simulate token refresh
        {
            let mut state = token_state.write().unwrap();
            *state = Some(TokenState {
                access_token: "new_token".to_string(),
                refresh_token: "new_refresh".to_string(),
                access_expires_at: now + ChronoDuration::seconds(900),
                refresh_expires_at: now + ChronoDuration::seconds(86400),
            });
        }

        // Verify update
        let state = token_state.read().unwrap();
        assert_eq!(state.as_ref().unwrap().access_token, "new_token");
        assert_eq!(state.as_ref().unwrap().refresh_token, "new_refresh");
    }

    #[test]
    fn test_token_expiry_logic() {
        let now = Utc::now();

        // Token expiring in 2 minutes - should refresh
        let expiring_soon = TokenState {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: now + ChronoDuration::seconds(120),
            refresh_expires_at: now + ChronoDuration::hours(12),
        };

        let time_until_expiry = expiring_soon.access_expires_at - now;
        assert!(
            time_until_expiry < ChronoDuration::minutes(3),
            "Token should be flagged for refresh when < 3 min until expiry"
        );

        // Token expiring in 10 minutes - should not refresh yet
        let not_expiring = TokenState {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: now + ChronoDuration::minutes(10),
            refresh_expires_at: now + ChronoDuration::hours(12),
        };

        let time_until_expiry = not_expiring.access_expires_at - now;
        assert!(
            time_until_expiry > ChronoDuration::minutes(3),
            "Token should not be flagged for refresh when > 3 min until expiry"
        );
    }

    #[test]
    fn test_refresh_token_expiry_logic() {
        let now = Utc::now();

        // Refresh token expiring in 2 hours - should re-authenticate
        let refresh_expiring_soon = TokenState {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: now + ChronoDuration::minutes(10),
            refresh_expires_at: now + ChronoDuration::hours(2),
        };

        let time_until_expiry = refresh_expiring_soon.refresh_expires_at - now;
        assert!(
            time_until_expiry < ChronoDuration::hours(4),
            "Should re-authenticate when refresh token expires in < 4 hours"
        );

        // Refresh token expiring in 12 hours - should not re-authenticate
        let refresh_not_expiring = TokenState {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: now + ChronoDuration::minutes(10),
            refresh_expires_at: now + ChronoDuration::hours(12),
        };

        let time_until_expiry = refresh_not_expiring.refresh_expires_at - now;
        assert!(
            time_until_expiry > ChronoDuration::hours(4),
            "Should not re-authenticate when refresh token has > 4 hours"
        );
    }

    #[test]
    fn test_token_state_clone() {
        let now = Utc::now();
        let token_state = TokenState {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: now + ChronoDuration::seconds(900),
            refresh_expires_at: now + ChronoDuration::seconds(86400),
        };

        let cloned = token_state.clone();

        assert_eq!(token_state.access_token, cloned.access_token);
        assert_eq!(token_state.refresh_token, cloned.refresh_token);
        assert_eq!(token_state.access_expires_at, cloned.access_expires_at);
        assert_eq!(token_state.refresh_expires_at, cloned.refresh_expires_at);
    }

    #[test]
    fn test_none_token_state_handling() {
        let token_state: Arc<RwLock<Option<TokenState>>> = Arc::new(RwLock::new(None));

        let state = token_state.read().unwrap();
        assert!(state.is_none(), "Initial state should be None");
    }
}
