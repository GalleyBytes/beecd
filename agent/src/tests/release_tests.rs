// Tests for actual util functions used throughout the agent
// These exercise production code paths for data transformation

#[cfg(test)]
mod util_tests {
    use crate::beecd;
    use crate::util::*;

    #[test]
    fn test_string_to_bytestring() {
        let s = "hello world".to_string();
        let bs = string_to_bytestring(s.clone());
        assert_eq!(bs.0, s.as_bytes());
    }

    #[test]
    fn test_bytestring_to_string() {
        let s = "test data".to_string();
        let bs = k8s_openapi::ByteString(s.as_bytes().to_vec());
        let result = bytestring_to_string(bs);
        assert_eq!(result, s);
    }

    #[test]
    fn test_bytestring_to_string_invalid_utf8() {
        let bs = k8s_openapi::ByteString(vec![0xFF, 0xFE, 0xFD]);
        let result = bytestring_to_string(bs);
        assert_eq!(result, "");
    }

    #[test]
    fn test_gzip_gunzip_roundtrip() {
        let data = b"test data for compression";
        let compressed = gzip_data(data).unwrap();
        let decompressed = gunzip_data(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_gunzipped_bytesstring() {
        let data = b"test data";
        let compressed = gzip_data(data).unwrap();
        let bs = k8s_openapi::ByteString(compressed);
        let result = gunzipped_bytesstring(bs).unwrap();
        assert_eq!(result.0, data);
    }

    #[test]
    fn test_gunzipped_bytesstring_invalid() {
        let bs = k8s_openapi::ByteString(vec![1, 2, 3, 4]);
        let result = gunzipped_bytesstring(bs);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_keyname_alphanumeric() {
        let result = safe_keyname("test-key-123".to_string()).unwrap();
        assert_eq!(result, "test.key.123");
    }

    #[test]
    fn test_safe_keyname_uppercase() {
        let result = safe_keyname("TestKey".to_string()).unwrap();
        assert_eq!(result, "testkey");
    }

    #[test]
    fn test_safe_keyname_special_chars() {
        let result = safe_keyname("test@key#name".to_string()).unwrap();
        assert_eq!(result, "test.key.name");
    }

    #[test]
    fn test_safe_keyname_trim_dots() {
        let result = safe_keyname("...test...".to_string()).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_safe_keyname_empty_error() {
        let result = safe_keyname("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_keyname_only_special_chars_error() {
        let result = safe_keyname("@#$%".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_to_bytestring() {
        let data = vec![1, 2, 3, 4, 5];
        let bs = bytes_to_bytestring(data.clone());
        assert_eq!(bs.0, data);
    }

    #[test]
    fn test_diff_data_as_k8s_secret_data_single() {
        let diff = vec![beecd::Diff {
            key: "test-key".to_string(),
            body: b"test data".to_vec(),
            change_order: vec![],
        }];
        let result = diff_data_as_k8s_secret_data(&diff);
        assert!(result.is_some());
        let map = result.unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("test.key"));
    }

    #[test]
    fn test_diff_data_as_k8s_secret_data_multiple() {
        let diffs = vec![
            beecd::Diff {
                key: "key1".to_string(),
                body: b"data1".to_vec(),
                change_order: vec![],
            },
            beecd::Diff {
                key: "key2".to_string(),
                body: b"data2".to_vec(),
                change_order: vec![],
            },
        ];
        let result = diff_data_as_k8s_secret_data(&diffs);
        assert!(result.is_some());
        let map = result.unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("key1"));
        assert!(map.contains_key("key2"));
    }

    #[test]
    fn test_diff_data_compression() {
        let diff = vec![beecd::Diff {
            key: "test".to_string(),
            body: b"test data that will be compressed".to_vec(),
            change_order: vec![],
        }];
        let result = diff_data_as_k8s_secret_data(&diff).unwrap();
        let compressed = result.get("test").unwrap();
        // Verify it's compressed by decompressing
        let decompressed = gunzip_data(&compressed.0).unwrap();
        assert_eq!(decompressed, b"test data that will be compressed");
    }

    #[test]
    fn test_diff_data_empty_vec() {
        let diffs: Vec<beecd::Diff> = vec![];
        let result = diff_data_as_k8s_secret_data(&diffs);
        assert!(result.is_none());
    }
}
