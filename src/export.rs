//! Export functionality for Vaultic
//!
//! Supports exporting vault entries to:
//! - Encrypted Vaultic backup format
//! - JSON (unencrypted)
//! - CSV (unencrypted)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{Cipher, CryptoError, MasterKey};
use crate::models::VaultEntry;

/// Export errors
#[derive(Debug, Error)]
pub enum ExportError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("No entries to export")]
    NoEntries,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type ExportResult<T> = Result<T, ExportError>;

/// Encrypted backup format metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    pub entry_count: usize,
    pub app_version: String,
}

/// Encrypted backup structure
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedBackup {
    pub metadata: BackupMetadata,
    pub encrypted_data: Vec<u8>,
}

/// JSON export format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonExport {
    pub version: u32,
    pub exported_at: String,
    pub entries: Vec<JsonEntry>,
}

/// Single entry in JSON export format
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
}

impl From<&VaultEntry> for JsonEntry {
    fn from(entry: &VaultEntry) -> Self {
        Self {
            name: entry.name.clone(),
            username: entry.username.clone(),
            password: entry.password.as_ref().map(|p| p.expose().to_string()),
            url: entry.url.clone(),
            tags: entry.tags.clone(),
            notes: entry.notes.as_ref().map(|n| n.expose().to_string()),
            folder: entry.folder.clone(),
            totp_secret: entry.totp_secret.as_ref().map(|t| t.expose().to_string()),
        }
    }
}

/// Export entries to encrypted Vaultic backup format
pub fn export_encrypted(entries: &[VaultEntry], master_key: &MasterKey) -> ExportResult<Vec<u8>> {
    if entries.is_empty() {
        return Err(ExportError::NoEntries);
    }

    let serialized = bincode::serialize(entries)
        .map_err(|e| ExportError::Serialization(e.to_string()))?;

    let derived = master_key.derive_keys();
    let cipher = Cipher::new(&derived.encryption_key);
    let encrypted_data = cipher.encrypt(&serialized)?;

    let metadata = BackupMetadata {
        version: 1,
        exported_at: Utc::now(),
        entry_count: entries.len(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let backup = EncryptedBackup { metadata, encrypted_data };
    bincode::serialize(&backup).map_err(|e| ExportError::Serialization(e.to_string()))
}

/// Export entries to JSON format (unencrypted)
pub fn export_json(entries: &[VaultEntry]) -> ExportResult<String> {
    let json_entries: Vec<JsonEntry> = entries.iter().map(JsonEntry::from).collect();
    let export = JsonExport {
        version: 1,
        exported_at: Utc::now().to_rfc3339(),
        entries: json_entries,
    };
    serde_json::to_string_pretty(&export).map_err(|e| ExportError::Serialization(e.to_string()))
}

/// Export entries to CSV format (unencrypted)
pub fn export_csv(entries: &[VaultEntry]) -> ExportResult<String> {
    let mut csv = String::from("name,username,password,url,tags,notes\n");
    for entry in entries {
        let row = format!(
            "{},{},{},{},{},{}\n",
            escape_csv(&entry.name),
            escape_csv(entry.username.as_deref().unwrap_or("")),
            escape_csv(entry.password.as_ref().map(|p| p.expose()).unwrap_or("")),
            escape_csv(entry.url.as_deref().unwrap_or("")),
            escape_csv(&entry.tags.join(";")),
            escape_csv(entry.notes.as_ref().map(|n| n.expose()).unwrap_or(""))
        );
        csv.push_str(&row);
    }
    Ok(csv)
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EntryType;

    #[test]
    fn test_export_json() {
        let entries = vec![
            VaultEntry::new("Test", EntryType::Password).with_password("secret"),
        ];
        let json = export_json(&entries).unwrap();
        assert!(json.contains("\"name\": \"Test\""));
    }

    #[test]
    fn test_export_csv() {
        let entries = vec![
            VaultEntry::new("Test", EntryType::Password).with_username("user"),
        ];
        let csv = export_csv(&entries).unwrap();
        assert!(csv.contains("Test,user"));
    }
}
