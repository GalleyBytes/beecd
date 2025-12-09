// Agent library exposing internal modules for testing
//
// This library file allows tests to access agent internals while keeping
// the binary in main.rs separate.

pub mod util;
pub mod beecd {
    tonic::include_proto!("beecd");
}
pub mod agent;

// Re-export key types for test convenience
pub use agent::Agent;
pub use beecd::*;

// Re-export chrono types for JWT token management
pub use chrono::Duration as ChronoDuration;
pub use k8s_openapi::chrono::Utc;

// Version constants used by agent.rs
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_VERSION: Option<&str> = option_env!("BUILD_VERSION");

// Test modules
#[cfg(test)]
pub mod tests;
