//! MCP (Model Context Protocol) server for Vaultic.
//!
//! This module implements an MCP server that allows AI assistants like Claude Code
//! to securely access credentials from the Vaultic vault without users having to
//! paste secrets in chat.
//!
//! # Architecture
//!
//! ```text
//! Claude Code ──(MCP/stdio)──► vaultic-mcp ──(Unix socket)──► vaultic-agent ──► Vault
//! ```
//!
//! # Security Model
//!
//! - Vault must be pre-unlocked via `vaultic unlock` (no password over MCP)
//! - Secret-access tools require user consent (prompted on the controlling
//!   terminal), or pre-authorization via the optional consent-policy config
//! - All credentials stay local (never sent to AI servers)
//! - Rate limiting prevents credential enumeration

pub mod config;
pub mod error;
pub mod server;
pub mod tools;

pub use config::McpConfig;
pub use error::McpError;
pub use server::VaulticMcpServer;
