//! MCP tool definitions for Vaultic.
//!
//! Tools are the primary way AI assistants interact with Vaultic. Each tool
//! maps to functionality in the vaultic-agent daemon.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
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

/// Result of asking the user for consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// The user approved access.
    Granted,
    /// The user explicitly declined.
    Denied,
    /// No controlling terminal was available to ask the user, so we could
    /// not obtain consent. Callers fail closed.
    Unavailable,
}

/// Handles user consent prompts for secret access.
///
/// The prompt is read from the controlling terminal (`/dev/tty`), **not**
/// stdin: the MCP server owns stdin/stdout for the JSON-RPC protocol, so
/// reading consent from stdin would steal protocol frames and corrupt the
/// stream. When there is no controlling terminal (e.g. the server was
/// launched by a GUI MCP host), consent is reported as `Unavailable` and the
/// caller denies access rather than leaking a secret unprompted.
pub struct ConsentHandler {
    require_consent: bool,
}

impl ConsentHandler {
    pub fn new(require_consent: bool) -> Self {
        Self { require_consent }
    }

    /// Whether consent is required at all (`--no-consent` sets this false).
    pub fn is_required(&self) -> bool {
        self.require_consent
    }

    /// Prompt for consent on the controlling terminal. This performs blocking
    /// terminal I/O, so async callers must run it via `spawn_blocking`.
    pub fn prompt_on_tty(action: &str, entry_name: &str) -> ConsentOutcome {
        // stdin/stdout are owned by the MCP transport — talk to the terminal
        // directly. If there is no controlling terminal, we cannot ask.
        let tty = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(f) => f,
            Err(_) => return ConsentOutcome::Unavailable,
        };

        let mut out = &tty;
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "┌─────────────────────────────────────────────────────────────┐"
        );
        let _ = writeln!(
            out,
            "│  VAULTIC: AI Credential Access Request                      │"
        );
        let _ = writeln!(
            out,
            "├─────────────────────────────────────────────────────────────┤"
        );
        let _ = writeln!(out, "│  Action: {:<50} │", action);
        let _ = writeln!(out, "│  Entry:  {:<50} │", entry_name);
        let _ = writeln!(
            out,
            "└─────────────────────────────────────────────────────────────┘"
        );
        let _ = write!(out, "Allow access? [y/N]: ");
        let _ = out.flush();

        let mut input = String::new();
        let mut reader = BufReader::new(&tty);
        if reader.read_line(&mut input).is_err() {
            return ConsentOutcome::Unavailable;
        }

        let allowed = input.trim().eq_ignore_ascii_case("y");
        let _ = writeln!(
            out,
            "{}",
            if allowed {
                "✓ Access granted"
            } else {
                "✗ Access denied"
            }
        );

        if allowed {
            ConsentOutcome::Granted
        } else {
            ConsentOutcome::Denied
        }
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
        self.requests
            .retain(|t| now.duration_since(*t) < self.window);

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
    ///
    /// Runs the blocking terminal prompt on a `spawn_blocking` thread so the
    /// tokio runtime is never stalled. Fails closed (`ConsentUnavailable`) if
    /// there is no controlling terminal to ask.
    pub async fn request_consent(&self, action: &str, entry_name: &str) -> Result<(), McpError> {
        if !self.consent.is_required() {
            return Ok(());
        }

        let action = action.to_string();
        let entry = entry_name.to_string();
        let outcome =
            tokio::task::spawn_blocking(move || ConsentHandler::prompt_on_tty(&action, &entry))
                .await
                .map_err(|e| McpError::Io(std::io::Error::other(e.to_string())))?;

        match outcome {
            ConsentOutcome::Granted => Ok(()),
            ConsentOutcome::Denied => Err(McpError::ConsentDenied),
            ConsentOutcome::Unavailable => Err(McpError::ConsentUnavailable),
        }
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
        assert!(!handler.is_required());
    }

    #[tokio::test]
    async fn consent_disabled_grants_without_tty() {
        // With consent disabled, request_consent must succeed without ever
        // touching /dev/tty (so it works in headless/test environments).
        let ctx = ToolContext::new(false);
        assert!(ctx.request_consent("get_password", "entry").await.is_ok());
    }
}
