//! MCP-specific error types.

use thiserror::Error;

use crate::agent::ClientError;

/// Errors that can occur in MCP operations.
#[derive(Debug, Error)]
pub enum McpError {
    /// Vault is locked - user must unlock first
    #[error("Vault is locked. Please run `vaultic unlock` first.")]
    VaultLocked,

    /// Entry not found
    #[error("Entry not found: {0}")]
    NotFound(String),

    /// User denied consent for secret access
    #[error("Access denied by user")]
    ConsentDenied,

    /// Agent communication error
    #[error("Agent error: {0}")]
    Agent(#[from] ClientError),

    /// Agent not running
    #[error("Vaultic agent is not running. Start it with `vaultic-agent start`.")]
    AgentNotRunning,

    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Rate limit exceeded
    #[error("Rate limit exceeded. Please wait before requesting more credentials.")]
    RateLimitExceeded,
}

impl McpError {
    /// Convert to a user-friendly message for the AI.
    pub fn to_ai_message(&self) -> String {
        match self {
            McpError::VaultLocked => {
                "The Vaultic vault is locked. Please ask the user to run `vaultic unlock` first."
                    .to_string()
            }
            McpError::NotFound(name) => {
                format!("No entry found matching '{}'. Use `list_entries` to see available entries.", name)
            }
            McpError::ConsentDenied => {
                "The user denied access to this credential.".to_string()
            }
            McpError::AgentNotRunning => {
                "The Vaultic agent is not running. Please ask the user to start it with `vaultic-agent start`."
                    .to_string()
            }
            McpError::RateLimitExceeded => {
                "Too many credential requests. Please wait a moment before trying again.".to_string()
            }
            _ => self.to_string(),
        }
    }
}
