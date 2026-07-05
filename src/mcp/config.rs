//! Optional consent-policy configuration for the MCP server.
//!
//! `vaultic-mcp` prompts for consent on the controlling terminal before
//! disclosing a secret. That works when the server is launched from a
//! terminal, but a GUI MCP host (Claude Desktop, etc.) has no TTY, so secret
//! tools would always fail closed.
//!
//! This config lets the user **pre-authorize** specific entries — by exact
//! name or by tag — so those disclosures are auto-approved without an
//! interactive prompt. Everything else still prompts (or fails closed without
//! a TTY). The file is entirely optional: with no config, behavior is
//! unchanged and nothing is auto-approved.
//!
//! # Format (`~/.config/vaultic/mcp.toml`)
//!
//! ```toml
//! [consent]
//! # Entry names (case-insensitive, exact match) the AI may read without a prompt.
//! auto_approve_names = ["GitHub CI", "Deploy Bot"]
//! # Any entry carrying one of these tags is auto-approved.
//! auto_approve_tags = ["ai-ok", "automation"]
//! ```
//!
//! # Security note
//!
//! Auto-approve trades the per-use consent prompt for standing authorization.
//! Only list entries you are comfortable an AI assistant reading unattended.
//! Every auto-approved disclosure is logged to stderr for visibility.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Errors loading the MCP config.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),

    #[error("could not read config {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

/// Top-level MCP configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Consent-policy settings.
    pub consent: ConsentConfig,
}

/// Consent-policy settings: which entries may be disclosed without a prompt.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ConsentConfig {
    /// Entry names (case-insensitive, exact) auto-approved for secret access.
    pub auto_approve_names: Vec<String>,
    /// Entry tags whose presence auto-approves an entry for secret access.
    pub auto_approve_tags: Vec<String>,
}

impl McpConfig {
    /// The default config path: `$XDG_CONFIG_HOME/vaultic/mcp.toml`
    /// (`~/.config/vaultic/mcp.toml` on Linux, `~/Library/Application
    /// Support/vaultic/mcp.toml` on macOS). `None` if no config dir resolves.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("vaultic").join("mcp.toml"))
    }

    /// Load config from an explicit path. The file must exist and parse.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Resolve config for the server:
    /// - `Some(path)`: an explicit `--config` — must exist and parse.
    /// - `None`: try the default path; use it if present, else an empty
    ///   (no-auto-approve) config. A malformed default file is still an error,
    ///   so a typo'd policy never silently authorizes nothing.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self, ConfigError> {
        match explicit {
            Some(p) => Self::load_from(p),
            None => match Self::default_path() {
                Some(p) if p.exists() => Self::load_from(&p),
                _ => Ok(Self::default()),
            },
        }
    }

    /// Whether any auto-approve rule is configured at all.
    pub fn has_auto_approve(&self) -> bool {
        !self.consent.auto_approve_names.is_empty() || !self.consent.auto_approve_tags.is_empty()
    }

    /// Whether an entry (by name + tags) is pre-authorized for disclosure
    /// without an interactive prompt.
    pub fn is_auto_approved(&self, name: &str, tags: &[String]) -> bool {
        let name_lc = name.to_lowercase();
        if self
            .consent
            .auto_approve_names
            .iter()
            .any(|allowed| allowed.to_lowercase() == name_lc)
        {
            return true;
        }
        if !self.consent.auto_approve_tags.is_empty() {
            let entry_tags: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
            if self
                .consent
                .auto_approve_tags
                .iter()
                .any(|allowed| entry_tags.contains(&allowed.to_lowercase()))
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_approves_nothing() {
        let c = McpConfig::default();
        assert!(!c.has_auto_approve());
        assert!(!c.is_auto_approved("GitHub", &["ai-ok".to_string()]));
    }

    #[test]
    fn parses_toml_and_matches_name_case_insensitively() {
        let c: McpConfig = toml::from_str(
            r#"
            [consent]
            auto_approve_names = ["GitHub CI"]
            "#,
        )
        .unwrap();
        assert!(c.has_auto_approve());
        assert!(c.is_auto_approved("github ci", &[]));
        assert!(c.is_auto_approved("GitHub CI", &[]));
        assert!(!c.is_auto_approved("GitHub", &[])); // exact, not substring
    }

    #[test]
    fn matches_by_tag_case_insensitively() {
        let c: McpConfig = toml::from_str(
            r#"
            [consent]
            auto_approve_tags = ["AI-OK"]
            "#,
        )
        .unwrap();
        assert!(c.is_auto_approved("Anything", &["personal".to_string(), "ai-ok".to_string()]));
        assert!(!c.is_auto_approved("Anything", &["personal".to_string()]));
    }

    #[test]
    fn missing_explicit_path_is_error() {
        let err = McpConfig::load_from(Path::new("/nonexistent/vaultic-mcp.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }

    #[test]
    fn empty_toml_is_valid_and_empty() {
        let c: McpConfig = toml::from_str("").unwrap();
        assert!(!c.has_auto_approve());
    }
}
