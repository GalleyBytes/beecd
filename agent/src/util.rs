use crate::{agent::AgentError, beecd};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use k8s_openapi::ByteString;
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub fn string_to_bytestring(s: String) -> k8s_openapi::ByteString {
    k8s_openapi::ByteString(s.as_bytes().to_vec())
}

#[allow(dead_code)]
pub fn bytestring_to_string(bs: k8s_openapi::ByteString) -> String {
    String::from_utf8(bs.0).unwrap_or_default()
}

pub fn gunzipped_bytesstring(
    bs: k8s_openapi::ByteString,
) -> Result<k8s_openapi::ByteString, AgentError> {
    let bytes = bs.0.to_vec();
    let gunzipped_bytes = gunzip_data(&bytes).map_err(AgentError::GunzipFailure)?;
    Ok(k8s_openapi::ByteString(gunzipped_bytes))
}

pub fn safe_keyname(s: String) -> Result<String, AgentError> {
    let mut output = s
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '.' })
        .collect::<String>();

    output = output.trim_matches('.').to_string();

    // Ensure the name is not empty
    if output.is_empty() {
        return Err(AgentError::DiffResourceKeyError);
    }

    Ok(output)
}

pub fn gzip_data(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

pub fn gunzip_data(
    compressed_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + 'static + Send + Sync>> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    Ok(decompressed_data)
}

pub fn bytes_to_bytestring(b: Vec<u8>) -> k8s_openapi::ByteString {
    k8s_openapi::ByteString(b)
}

pub fn diff_data_as_k8s_secret_data(
    diff_data: &[beecd::Diff],
) -> Option<BTreeMap<String, k8s_openapi::ByteString>> {
    diff_data
        .iter()
        .fold::<Option<BTreeMap<String, ByteString>>, _>(None, |b, diff| {
            let diff_key = safe_keyname(diff.key.clone()).unwrap();
            if let Some(mut map) = b {
                map.insert(
                    diff_key,
                    bytes_to_bytestring(gzip_data(&diff.body.clone()).unwrap()),
                );
                Some(map)
            } else {
                let mut map: BTreeMap<String, ByteString> = BTreeMap::new();
                map.insert(
                    diff_key,
                    bytes_to_bytestring(gzip_data(&diff.body.clone()).unwrap()),
                );
                Some(map)
            }
        })
}
