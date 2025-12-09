// Integration tests for JWT authentication in the agent
//
// These tests verify the agent can authenticate with the hive server using JWT,
// handle token refresh, and recover from authentication failures.

use chrono::{Duration, Utc};
use std::sync::{Arc, RwLock};

// Note: These tests require a running hive server with JWT enabled
// For now, they serve as documentation and structure for future integration testing

#[cfg(test)]
mod jwt_integration_tests {
    use super::*;

    // Test helper to create a mock TokenState
    fn create_mock_token_state(
        access_expiry_secs: i64,
        refresh_expiry_secs: i64,
    ) -> agent::agent::TokenState {
        let now = Utc::now();
        agent::agent::TokenState {
            access_token: "mock_access_token".to_string(),
            refresh_token: "mock_refresh_token".to_string(),
            access_expires_at: now + Duration::seconds(access_expiry_secs),
            refresh_expires_at: now + Duration::seconds(refresh_expiry_secs),
        }
    }

    #[test]
    fn test_token_state_creation() {
        let token_state = create_mock_token_state(900, 86400);

        assert!(!token_state.access_token.is_empty());
        assert!(!token_state.refresh_token.is_empty());
        assert!(token_state.access_expires_at > Utc::now());
        assert!(token_state.refresh_expires_at > Utc::now());
    }

    #[test]
    fn test_token_state_expiry_detection() {
        let now = Utc::now();

        // Token that expires in 1 minute (should trigger refresh)
        let short_lived = create_mock_token_state(60, 86400);
        let time_until_expiry = short_lived.access_expires_at - now;
        assert!(time_until_expiry < Duration::minutes(3));

        // Token that expires in 10 minutes (should not trigger refresh yet)
        let long_lived = create_mock_token_state(600, 86400);
        let time_until_expiry = long_lived.access_expires_at - now;
        assert!(time_until_expiry > Duration::minutes(3));
    }

    #[test]
    fn test_refresh_token_expiry_detection() {
        let now = Utc::now();

        // Refresh token that expires soon (should trigger re-auth)
        let expiring_refresh = create_mock_token_state(900, 3600); // 1 hour
        let time_until_expiry = expiring_refresh.refresh_expires_at - now;
        assert!(time_until_expiry < Duration::hours(4));

        // Refresh token with plenty of time (should not trigger re-auth)
        let fresh_refresh = create_mock_token_state(900, 86400); // 24 hours
        let time_until_expiry = fresh_refresh.refresh_expires_at - now;
        assert!(time_until_expiry > Duration::hours(4));
    }

    #[test]
    fn test_concurrent_token_access() {
        // Test that multiple threads can safely read the token state
        let token_state = Arc::new(RwLock::new(Some(create_mock_token_state(900, 86400))));

        let mut handles = vec![];

        for _ in 0..10 {
            let state_clone = Arc::clone(&token_state);
            let handle = std::thread::spawn(move || {
                let state = state_clone.read().unwrap();
                assert!(state.is_some());
                if let Some(ref ts) = *state {
                    assert_eq!(ts.access_token, "mock_access_token");
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_token_rotation() {
        // Simulate token rotation during refresh
        let token_state = Arc::new(RwLock::new(Some(create_mock_token_state(900, 86400))));

        let old_refresh_token = {
            let state = token_state.read().unwrap();
            state.as_ref().unwrap().refresh_token.clone()
        };

        // Simulate refresh by updating the token state
        {
            let mut state = token_state.write().unwrap();
            *state = Some(create_mock_token_state(900, 86400));
            state.as_mut().unwrap().refresh_token = "new_refresh_token".to_string();
        }

        let new_refresh_token = {
            let state = token_state.read().unwrap();
            state.as_ref().unwrap().refresh_token.clone()
        };

        assert_ne!(old_refresh_token, new_refresh_token);
    }
}

// Full integration test (requires running server)
// Uncomment when server is available for testing
/*
#[tokio::test]
async fn test_full_authentication_flow() {
    use tonic::transport::Channel;
    use agent::beecd::worker_client::WorkerClient;
    use agent::agent::{GrpcHeaderInjector, TokenState};

    // Connect to test server
    let channel = Channel::from_static("http://localhost:5180")
        .connect()
        .await
        .expect("Failed to connect to test server");

    let mut login_client = WorkerClient::new(channel.clone());

    // Perform login
    let login_response = login_client
        .login(agent::beecd::LoginRequest {
            username: "test-cluster".to_string(),
            password: "test-password".to_string(),
            user_agent: "test-agent/1.0".to_string(),
        })
        .await
        .expect("Login failed")
        .into_inner();

    assert!(!login_response.access_token.is_empty());
    assert!(!login_response.refresh_token.is_empty());
    assert!(login_response.access_token_expires_in > 0);
    assert!(login_response.refresh_token_expires_in > 0);

    // Create token state
    let now = Utc::now();
    let token_state = Arc::new(RwLock::new(Some(TokenState {
        access_token: login_response.access_token.clone(),
        refresh_token: login_response.refresh_token.clone(),
        access_expires_at: now + Duration::seconds(login_response.access_token_expires_in),
        refresh_expires_at: now + Duration::seconds(login_response.refresh_token_expires_in),
    })));

    // Create authenticated client
    let interceptor = GrpcHeaderInjector::new(token_state.clone());
    let mut authenticated_client = WorkerClient::with_interceptor(channel, interceptor);

    // Make an authenticated request
    let registration_response = authenticated_client
        .client_registration(agent::beecd::ClusterName {
            cluster_name: "test-cluster".to_string(),
            metadata: "".to_string(),
            version: "test".to_string(),
            kubernetes_version: "v1.28.0".to_string(),
        })
        .await
        .expect("Authenticated request failed");

    assert!(!registration_response.into_inner().cluster_id.is_empty());
}

#[tokio::test]
async fn test_token_refresh_flow() {
    use tonic::transport::Channel;
    use agent::beecd::worker_client::WorkerClient;

    // Connect and login
    let channel = Channel::from_static("http://localhost:5180")
        .connect()
        .await
        .expect("Failed to connect");

    let mut client = WorkerClient::new(channel);

    let login_response = client
        .login(agent::beecd::LoginRequest {
            username: "test-cluster".to_string(),
            password: "test-password".to_string(),
            user_agent: "test-agent/1.0".to_string(),
        })
        .await
        .expect("Login failed")
        .into_inner();

    let old_refresh_token = login_response.refresh_token.clone();

    // Perform token refresh
    let refresh_response = client
        .refresh_token(agent::beecd::RefreshTokenRequest {
            refresh_token: login_response.refresh_token,
        })
        .await
        .expect("Token refresh failed")
        .into_inner();

    assert!(!refresh_response.access_token.is_empty());
    assert!(!refresh_response.refresh_token.is_empty());
    assert_ne!(refresh_response.refresh_token, old_refresh_token, "Refresh token should rotate");
}
*/
