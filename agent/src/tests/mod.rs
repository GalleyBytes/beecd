// Test module organization for agent
// This module contains all internal unit and integration tests for the agent crate

pub mod common;
pub mod fixtures;
pub mod mocks;

// Comprehensive util.rs tests (all helper functions)
pub mod release_tests;

// Core agent functionality tests
pub mod agent_core_tests;

// Unit tests for Resource struct and diffing
pub mod resource_tests;

// Secret management tests
pub mod secret_tests;

// Retry and conflict handling tests
pub mod retry_tests;

// Manifest diffing tests
pub mod diff_tests;

// Weighted resource ordering tests
pub mod weighted_tests;

// JWT authentication tests
pub mod auth_tests;
