//! Vaultic - A secure, local-first password manager
//!
//! # Features
//! - **FIDO2/YubiKey Authentication**: Passwordless unlock with hardware security keys
//! - **End-to-End Encryption**: XChaCha20-Poly1305 + Argon2id
//! - **AI-Powered Management**: Local AI suggestions for password hygiene
//! - **Secure Sharing**: Asymmetric encryption for password sharing
//! - **GPG Integration**: Use existing GPG keys
//! - **Beautiful CLI**: Fuzzy search, interactive TUI, QR codes
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        CLI / TUI                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Sharing  │    AI     │   FIDO2   │   GPG    │   TOTP      │
//! ├───────────┴───────────┴───────────┴──────────┴─────────────┤
//! │                     Core (Models)                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                     Crypto Layer                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Storage (sled DB)                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//! ```bash
//! # Initialize a new vault
//! vaultic init --fido2
//!
//! # Add an entry
//! vaultic add "GitHub" -u "user@example.com" --generate
//!
//! # Search entries
//! vaultic search
//!
//! # Get AI suggestions
//! vaultic suggest --analyze
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod ai;
pub mod cli;
pub mod crypto;
pub mod fido2;
pub mod gpg;
pub mod models;
pub mod session;
pub mod sharing;
pub mod storage;
pub mod totp;
pub mod tui;

// Re-exports for convenience
pub use crypto::{Cipher, MasterKey, PasswordAnalyzer, PasswordGenerator};
pub use models::{EntryType, PasswordStrength, SensitiveString, VaultEntry, VaultMetadata};
pub use storage::{VaultStorage, StorageError};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default vault path
pub fn default_vault_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".vaultic")
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to vault directory
    pub vault_path: std::path::PathBuf,
    /// Session timeout in minutes (0 = no timeout)
    pub session_timeout: u32,
    /// Clipboard auto-clear timeout in seconds
    pub clipboard_timeout: u32,
    /// AI backend configuration
    pub ai_backend: AiBackend,
    /// Enable breach checking
    pub check_breaches: bool,
    /// Default password length
    pub default_password_length: usize,
    /// Default rotation days
    pub default_rotation_days: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            session_timeout: 15,
            clipboard_timeout: 30,
            ai_backend: AiBackend::default(),
            check_breaches: true,
            default_password_length: 20,
            default_rotation_days: 90,
        }
    }
}

/// AI backend configuration
#[derive(Debug, Clone)]
pub enum AiBackend {
    /// Local Ollama instance
    Ollama {
        url: String,
        model: String,
    },
    /// Local llama.cpp server
    LlamaCpp {
        url: String,
    },
    /// Disabled - use rule-based analysis only
    Disabled,
}

impl Default for AiBackend {
    fn default() -> Self {
        Self::Ollama {
            url: "http://localhost:11434".to_string(),
            model: "llama3.2:3b".to_string(),
        }
    }
}

/// Vault session state
pub struct VaultSession {
    storage: VaultStorage,
    config: Config,
    unlocked_at: Option<std::time::Instant>,
}

impl VaultSession {
    /// Create a new session
    pub fn new(storage: VaultStorage, config: Config) -> Self {
        Self {
            storage,
            config,
            unlocked_at: None,
        }
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self) -> bool {
        if self.config.session_timeout == 0 {
            return false;
        }

        match self.unlocked_at {
            Some(time) => {
                time.elapsed().as_secs() > (self.config.session_timeout as u64 * 60)
            }
            None => true,
        }
    }

    /// Mark session as unlocked
    pub fn mark_unlocked(&mut self) {
        self.unlocked_at = Some(std::time::Instant::now());
    }

    /// Lock the session
    pub fn lock(&mut self) {
        self.unlocked_at = None;
        self.storage.lock();
    }

    /// Get storage reference
    pub fn storage(&self) -> &VaultStorage {
        &self.storage
    }

    /// Get mutable storage reference
    pub fn storage_mut(&mut self) -> &mut VaultStorage {
        &mut self.storage
    }

    /// Get config reference
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// Error type for the library
#[derive(Debug, thiserror::Error)]
pub enum VaulticError {
    /// Storage errors
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    /// Crypto errors
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    /// FIDO2 errors
    #[error("FIDO2 error: {0}")]
    Fido2(#[from] fido2::Fido2Error),

    /// Sharing errors
    #[error("Sharing error: {0}")]
    Sharing(#[from] sharing::SharingError),

    /// GPG errors
    #[error("GPG error: {0}")]
    Gpg(#[from] gpg::GpgError),

    /// AI errors
    #[error("AI error: {0}")]
    Ai(#[from] ai::AiError),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Session timeout
    #[error("Session timed out")]
    SessionTimeout,

    /// Vault locked
    #[error("Vault is locked")]
    VaultLocked,

    /// Entry not found
    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type for the library
pub type VaulticResult<T> = Result<T, VaulticError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.session_timeout, 15);
        assert_eq!(config.clipboard_timeout, 30);
        assert_eq!(config.default_password_length, 20);
    }

    #[test]
    fn test_default_vault_path() {
        let path = default_vault_path();
        assert!(path.ends_with(".vaultic"));
    }
}
