//! MCP tool definitions for Vaultic.
//!
//! Tools are the primary way AI assistants interact with Vaultic. Each tool
//! maps to functionality in the vaultic-agent daemon.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::agent::protocol::EntrySummary;
use crate::mcp::error::McpError;

/// Parameters for list_entries tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEntriesParams {
    /// Optional search query to filter entries
    #[serde(default)]
    pub query: Option<String>,
    /// Filter by folder
    #[serde(default)]
    pub folder: Option<String>,
    /// Filter by tags (entries must have all specified tags)
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Parameters for get_password tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPasswordParams {
    /// Entry ID (UUID) - use this if you have the exact ID from list_entries
    #[serde(default)]
    pub entry_id: Option<String>,
    /// Entry name - use this for fuzzy matching if you don't have the ID
    #[serde(default)]
    pub name: Option<String>,
}

/// Parameters for get_credential tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCredentialParams {
    /// Entry ID (UUID) - use this if you have the exact ID from list_entries
    #[serde(default)]
    pub entry_id: Option<String>,
    /// Entry name - use this for fuzzy matching if you don't have the ID
    #[serde(default)]
    pub name: Option<String>,
}

/// Parameters for get_totp tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTotpParams {
    /// Entry ID (UUID) - use this if you have the exact ID from list_entries
    #[serde(default)]
    pub entry_id: Option<String>,
    /// Entry name - use this for fuzzy matching if you don't have the ID
    #[serde(default)]
    pub name: Option<String>,
}

/// Parameters for search_entries tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchEntriesParams {
    /// Search query (fuzzy matches name, username, URL, tags)
    pub query: String,
}

/// Result of vault_status tool.
#[derive(Debug, Serialize, JsonSchema)]
pub struct VaultStatusResult {
    /// Whether the vault is currently locked
    pub locked: bool,
    /// Path to the vault directory
    pub vault_path: Option<String>,
    /// Number of entries in the vault (if unlocked)
    pub entry_count: Option<usize>,
    /// When the session expires (ISO 8601 timestamp)
    pub expires_at: Option<String>,
}

/// Result of get_credential tool.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialResult {
    /// The username
    pub username: Option<String>,
    /// The password
    pub password: String,
    /// The URL associated with this credential
    pub url: Option<String>,
}

/// Result of get_totp tool.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TotpResult {
    /// The current TOTP code
    pub code: String,
    /// Seconds remaining until the code changes
    pub remaining_seconds: u32,
}

/// Handles user consent prompts for secret access.
pub struct ConsentHandler {
    require_consent: bool,
}

impl ConsentHandler {
    pub fn new(require_consent: bool) -> Self {
        Self { require_consent }
    }

    /// Prompt user for consent to access a secret.
    /// Returns true if access is granted, false if denied.
    pub fn prompt(&self, action: &str, entry_name: &str) -> io::Result<bool> {
        if !self.require_consent {
            return Ok(true);
        }

        // Write to stderr since stdout is used for MCP protocol
        eprintln!();
        eprintln!("┌─────────────────────────────────────────────────────────────┐");
        eprintln!("│  VAULTIC: AI Credential Access Request                      │");
        eprintln!("├─────────────────────────────────────────────────────────────┤");
        eprintln!("│  Action: {:<50} │", action);
        eprintln!("│  Entry:  {:<50} │", entry_name);
        eprintln!("└─────────────────────────────────────────────────────────────┘");
        eprint!("Allow access? [y/N]: ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let allowed = input.trim().eq_ignore_ascii_case("y");

        if allowed {
            eprintln!("✓ Access granted");
        } else {
            eprintln!("✗ Access denied");
        }

        Ok(allowed)
    }
}

/// Rate limiter for secret access.
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Window duration
    window: Duration,
    /// Request timestamps
    requests: Vec<Instant>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            requests: Vec::new(),
        }
    }

    /// Check if a request is allowed. Returns true if allowed.
    pub fn check(&mut self) -> bool {
        let now = Instant::now();

        // Remove old requests outside the window
        self.requests.retain(|t| now.duration_since(*t) < self.window);

        if self.requests.len() >= self.max_requests as usize {
            return false;
        }

        self.requests.push(now);
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // 10 secret accesses per minute
        Self::new(10, Duration::from_secs(60))
    }
}

/// Tool execution context with agent client and consent handler.
pub struct ToolContext {
    pub consent: ConsentHandler,
    pub rate_limiter: Mutex<RateLimiter>,
}

impl ToolContext {
    pub fn new(require_consent: bool) -> Self {
        Self {
            consent: ConsentHandler::new(require_consent),
            rate_limiter: Mutex::new(RateLimiter::default()),
        }
    }

    /// Check rate limit for secret access.
    pub async fn check_rate_limit(&self) -> Result<(), McpError> {
        let mut limiter = self.rate_limiter.lock().await;
        if !limiter.check() {
            return Err(McpError::RateLimitExceeded);
        }
        Ok(())
    }

    /// Request consent for secret access.
    pub fn request_consent(&self, action: &str, entry_name: &str) -> Result<(), McpError> {
        if !self.consent.prompt(action, entry_name).map_err(McpError::Io)? {
            return Err(McpError::ConsentDenied);
        }
        Ok(())
    }
}

/// Convert EntrySummary to a JSON-serializable format.
#[derive(Debug, Serialize, JsonSchema)]
pub struct EntryInfo {
    /// Unique identifier for this entry
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Username/email associated with this entry
    pub username: Option<String>,
    /// URL for this credential
    pub url: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Folder path
    pub folder: Option<String>,
    /// Whether this is a favorite
    pub favorite: bool,
    /// Whether this entry has a password
    pub has_password: bool,
    /// Whether this entry has TOTP configured
    pub has_totp: bool,
    /// Entry type (password, note, card, identity, ssh_key)
    pub entry_type: String,
}

impl From<EntrySummary> for EntryInfo {
    fn from(s: EntrySummary) -> Self {
        Self {
            id: s.id.to_string(),
            name: s.name,
            username: s.username,
            url: s.url,
            tags: s.tags,
            folder: s.folder,
            favorite: s.favorite,
            has_password: s.has_password,
            has_totp: s.has_totp,
            entry_type: format!("{:?}", s.entry_type).to_lowercase(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(1));
        assert!(limiter.check());
        assert!(limiter.check());
        assert!(!limiter.check()); // Third request should be denied
    }

    #[test]
    fn test_consent_handler_disabled() {
        let handler = ConsentHandler::new(false);
        // When consent is disabled, always returns true
        assert!(handler.prompt("test", "entry").unwrap());
    }
}
