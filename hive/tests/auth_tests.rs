use base64::{engine::general_purpose, Engine as _};

#[test]
fn test_basic_auth_encoding() {
    let user = "testuser";
    let password = "testpass";

    let mut buf = String::new();
    general_purpose::STANDARD.encode_string(format!("{}:{}", user, password).as_bytes(), &mut buf);

    let basic_token = format!("Basic {}", buf);

    // Verify the encoding
    assert!(basic_token.starts_with("Basic "));
    assert!(!buf.is_empty());

    // Decode and verify
    let decoded = general_purpose::STANDARD
        .decode(buf.as_bytes())
        .expect("Failed to decode");
    let decoded_str = String::from_utf8(decoded).expect("Failed to convert to string");

    assert_eq!(decoded_str, format!("{}:{}", user, password));
}

#[test]
fn test_basic_auth_decoding() {
    let user = "admin";
    let password = "secret123";

    // Encode
    let credentials = format!("{}:{}", user, password);
    let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
    let header_value = format!("Basic {}", encoded);

    // Decode logic (similar to what's in auth.rs)
    let parts: Vec<&str> = header_value.split(' ').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], "Basic");

    let decoded_bytes = general_purpose::STANDARD
        .decode(parts[1])
        .expect("Failed to decode");
    let decoded_str = String::from_utf8(decoded_bytes).expect("Failed to convert to string");

    let mut cred_parts = decoded_str.split(':');
    let decoded_user = cred_parts.next().unwrap();
    let decoded_password = cred_parts.next().unwrap();

    assert_eq!(decoded_user, user);
    assert_eq!(decoded_password, password);
}

#[test]
fn test_invalid_basic_auth_format() {
    let invalid_header = "Bearer some-token";

    let parts: Vec<&str> = invalid_header.split(' ').collect();
    assert_ne!(parts[0], "Basic", "Should not be Basic auth");
}

#[test]
fn test_basic_auth_with_special_chars() {
    let user = "user@example.com";
    let password = "p@$$w0rd!";

    let mut buf = String::new();
    general_purpose::STANDARD.encode_string(format!("{}:{}", user, password).as_bytes(), &mut buf);

    // Decode and verify
    let decoded = general_purpose::STANDARD
        .decode(buf.as_bytes())
        .expect("Failed to decode");
    let decoded_str = String::from_utf8(decoded).expect("Failed to convert to string");

    assert_eq!(decoded_str, format!("{}:{}", user, password));
}

#[test]
fn test_password_hashing_and_verification() {
    let password = "my_secure_password";

    // Hash the password
    let hash = bcrypt::hash(password, 4).expect("Failed to hash password");

    // Verify correct password
    let is_valid = bcrypt::verify(password, &hash).expect("Failed to verify password");
    assert!(is_valid, "Password should be valid");

    // Verify incorrect password
    let is_invalid = bcrypt::verify("wrong_password", &hash).expect("Failed to verify password");
    assert!(!is_invalid, "Wrong password should not be valid");
}

#[test]
fn test_password_hash_uniqueness() {
    let password = "same_password";

    // Hash the same password twice
    let hash1 = bcrypt::hash(password, 4).expect("Failed to hash password");
    let hash2 = bcrypt::hash(password, 4).expect("Failed to hash password");

    // Hashes should be different (due to salting)
    assert_ne!(hash1, hash2, "Hashes should differ due to different salts");

    // But both should verify correctly
    assert!(
        bcrypt::verify(password, &hash1).unwrap(),
        "First hash should verify"
    );
    assert!(
        bcrypt::verify(password, &hash2).unwrap(),
        "Second hash should verify"
    );
}

#[test]
fn test_empty_password() {
    let password = "";

    let hash = bcrypt::hash(password, 4).expect("Failed to hash empty password");
    let is_valid = bcrypt::verify(password, &hash).expect("Failed to verify empty password");

    assert!(is_valid, "Empty password should still hash and verify");
}

#[test]
fn test_long_password() {
    let password = "a".repeat(100);

    let hash = bcrypt::hash(&password, 4).expect("Failed to hash long password");
    let is_valid = bcrypt::verify(&password, &hash).expect("Failed to verify long password");

    assert!(is_valid, "Long password should hash and verify correctly");
}
