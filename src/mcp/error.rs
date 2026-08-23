//! MCP-specific error types.

use thiserror::Error;

use crate::agent::protocol::ErrorCode;
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

    /// Consent could not be obtained because there is no controlling terminal
    #[error("Consent unavailable: no controlling terminal to prompt on. Run vaultic-mcp from a terminal, or use --no-consent in a trusted environment.")]
    ConsentUnavailable,

    /// Agent communication error
    #[error("Agent error: {0}")]
    Agent(ClientError),

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

/// Map an agent client error into the most specific `McpError`.
///
/// A locked vault is the single most common failure (the vault must be
/// pre-unlocked), so surface it as `VaultLocked` with an actionable message
/// instead of a raw `Agent(...)`. `NotFound` without an entry name is left as
/// `Agent` — the tool call sites that know the name build a richer
/// `NotFound(name)` themselves.
impl From<ClientError> for McpError {
    fn from(e: ClientError) -> Self {
        match e.agent_code() {
            Some(ErrorCode::VaultLocked) => McpError::VaultLocked,
            _ => McpError::Agent(e),
        }
    }
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
            McpError::ConsentUnavailable => {
                "Cannot ask the user for consent: vaultic-mcp has no controlling terminal. \
                 Ask the user to run it from a terminal, or start it with --no-consent in a trusted environment."
                    .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::protocol::AgentError;

    #[test]
    fn client_vault_locked_maps_to_vault_locked() {
        let ce = ClientError::Agent(AgentError {
            code: ErrorCode::VaultLocked,
            message: "vault is locked".to_string(),
        });
        let me: McpError = ce.into();
        assert!(matches!(me, McpError::VaultLocked));
        // The friendly, actionable message is now reachable.
        assert!(me.to_ai_message().contains("vaultic unlock"));
    }

    #[test]
    fn other_agent_errors_stay_agent() {
        let ce = ClientError::Agent(AgentError {
            code: ErrorCode::VaultIo,
            message: "disk error".to_string(),
        });
        let me: McpError = ce.into();
        assert!(matches!(me, McpError::Agent(_)));
    }
}
