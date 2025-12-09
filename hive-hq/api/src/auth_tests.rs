// Unit tests for ACL and authentication features
// These tests can be run without the full integration test environment
// Run with: cargo test -p api --lib

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use types::Claim;

    #[test]
    fn test_claim_struct_supports_multiple_roles() {
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600);

        let claim = Claim {
            email: "test@example.com".to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec!["admin".to_string(), "aversion".to_string()],
        };

        assert_eq!(claim.roles.len(), 2);
        assert!(claim.roles.contains(&"admin".to_string()));
        assert!(claim.roles.contains(&"aversion".to_string()));
    }

    #[test]
    fn test_jwt_encoding_with_admin_role() {
        let jwt_secret = "test_secret";
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600);

        let claims = Claim {
            email: "admin@galleybytes.com".to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec!["admin".to_string()],
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .expect("Failed to encode JWT");

        assert!(!token.is_empty());

        // Verify we can decode it
        let decoded = decode::<Claim>(
            &token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.email, "admin@galleybytes.com");
        assert_eq!(decoded.claims.roles.len(), 1);
        assert_eq!(decoded.claims.roles[0], "admin");
    }

    #[test]
    fn test_jwt_encoding_with_aversion_role() {
        let jwt_secret = "test_secret";
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600);

        let claims = Claim {
            email: "aversion@galleybytes.com".to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec!["aversion".to_string()],
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let decoded = decode::<Claim>(
            &token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.email, "aversion@galleybytes.com");
        assert_eq!(decoded.claims.roles.len(), 1);
        assert_eq!(decoded.claims.roles[0], "aversion");
    }

    #[test]
    fn test_jwt_with_multiple_roles() {
        let jwt_secret = "test_secret";
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600);

        let claims = Claim {
            email: "multiuser@galleybytes.com".to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec![
                "admin".to_string(),
                "aversion".to_string(),
                "operator".to_string(),
            ],
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let decoded = decode::<Claim>(
            &token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.roles.len(), 3);
        assert!(decoded.claims.roles.contains(&"admin".to_string()));
        assert!(decoded.claims.roles.contains(&"aversion".to_string()));
        assert!(decoded.claims.roles.contains(&"operator".to_string()));
    }

    #[test]
    fn test_role_checking_logic() {
        let user_roles = ["aversion".to_string(), "viewer".to_string()];
        let required_roles = ["aversion".to_string(), "admin".to_string()];

        // Check if user has at least one of the required roles
        let has_required_role = user_roles.iter().any(|role| required_roles.contains(role));

        assert!(
            has_required_role,
            "User should have access with aversion role"
        );
    }

    #[test]
    fn test_role_checking_denied() {
        let user_roles = ["viewer".to_string(), "guest".to_string()];
        let required_roles = ["aversion".to_string(), "admin".to_string()];

        let has_required_role = user_roles.iter().any(|role| required_roles.contains(role));

        assert!(
            !has_required_role,
            "User should not have access without required roles"
        );
    }

    #[test]
    fn test_admin_has_access() {
        let user_roles = ["admin".to_string()];
        let required_roles = ["aversion".to_string(), "admin".to_string()];

        let has_required_role = user_roles.iter().any(|role| required_roles.contains(role));

        assert!(has_required_role, "Admin should have access");
    }

    #[test]
    fn test_role_checking_with_slices() {
        // Test that role checking works with string slices (optimization)
        let user_roles = ["aversion".to_string()];
        let required_roles: &[&str] = &["aversion", "admin"];

        let has_required_role = user_roles
            .iter()
            .any(|role| required_roles.contains(&role.as_str()));

        assert!(has_required_role, "Slice-based role checking should work");
    }
}
