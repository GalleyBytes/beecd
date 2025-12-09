use base64::{engine::general_purpose, Engine as _};
use bcrypt::hash;
use rand::TryRngCore;
use rand::{random_range, rng};
use sha2::{Digest, Sha256};
use std::fmt;

use tinytemplate::TinyTemplate;

#[derive(Debug)]
struct Serror(String);

impl fmt::Display for Serror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for Serror {}

pub fn generate_random_string(length: u32) -> String {
    let _rng = rng();
    (0..length)
        .map(|_| loop {
            let ch = random_range(32..126) as u8 as char;
            if ![
                '\'', '"', '`', '\\', '.', ':', ';', ' ', '^', '!', '$', '%', '+',
            ]
            .contains(&ch)
            {
                break ch;
            }
        })
        .collect()
}

/// Generate a cryptographically secure 256-bit (32 byte) token.
///
/// Returned as URL-safe base64 without padding, suitable for cookies.
pub fn generate_secure_token_256() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| String::from("Failed to read OS random"))?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub fn bcrypt_string(input: &str) -> Result<String, bcrypt::BcryptError> {
    hash(input, 13)
}

/// Hash a string using SHA256 and return the hex representation
pub fn hash_string(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_manifest(
    template: &str,
    context: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut tt = TinyTemplate::new();
    tt.add_template("manifest", template)?;

    tt.add_formatter("yaml", |data, rendered| {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&data.to_string()).map_err(|e| {
            tinytemplate::error::Error::GenericError {
                msg: format!("Failed parsing yaml value {:?}: {}", data, e),
            }
        })?;
        let indent = match rendered.split("\n").last() {
            Some(s) => " ".repeat(s.len()),
            None => String::new(),
        };
        let raw_yaml =
            serde_yaml::to_string(&yaml).map_err(|e| tinytemplate::error::Error::GenericError {
                msg: format!("Failed serializing yaml {:?}: {}", yaml, e),
            })?;

        let formatted_yaml = raw_yaml
            .split("\n")
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
            .map(|(line_index, line)| {
                if line_index == 0 {
                    String::from(*line)
                } else {
                    format!("{}{}", indent, line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        *rendered = format!("{}{}", rendered, formatted_yaml);
        Ok(())
    });

    tt.render("manifest", &context).map_err(|e| e.into())
}

/// value looks at the string type value sent in, and if is None, sets a default value.
///
/// When required is true, the final value must not be an empty.
pub fn value_or_default(
    value_op: Option<&serde_json::Value>,
    default_op: Option<String>,
    required: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let default = default_op.unwrap_or_default();

    let value = value_op.map_or(serde_json::Value::String(default.clone()), |v| v.clone());

    if required && value_op.is_none() && default.is_empty() {
        Err(Box::new(Serror(String::from(
            "Value set as required but was missing or empty",
        ))))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_manifest_grpc_tls_is_quoted_string() {
        let template = include_str!("static/agent.tpl.yaml");
        let rendered = generate_manifest(
            template,
            serde_json::json!({
                "agent_name": "agent",
                "namespace": "beecd",
                // Secret data in the template is expected to already be base64.
                "secret": "c2VjcmV0",
                "image": "ghcr.io/beecd/agent:latest",
                "name": "cluster-1",
                "grpc_address": "hive.example.com:443",
                // Handler code stringifies this as "true"/"false".
                "grpc_tls": "false",
                "env": [],
            }),
        )
        .unwrap();

        let mut found = false;
        let lines: Vec<&str> = rendered.lines().collect();
        for i in 0..lines.len().saturating_sub(1) {
            if lines[i].contains("name: GRPC_TLS") {
                found = true;
                assert!(
                    lines[i + 1].contains("value: \"false\""),
                    "GRPC_TLS should be a quoted string; got: {}",
                    lines[i + 1]
                );
                break;
            }
        }

        assert!(found, "Expected GRPC_TLS env var in rendered manifest");
    }
}
