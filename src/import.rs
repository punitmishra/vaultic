//! Import functionality for Vaultic
//!
//! Supports importing entries from:
//! - Encrypted Vaultic backup format
//! - Bitwarden JSON export
//! - LastPass CSV export
//! - 1Password CSV export

use serde::Deserialize;
use thiserror::Error;

use crate::crypto::{Cipher, CryptoError, MasterKey};
use crate::export::EncryptedBackup;
use crate::models::{EntryType, SensitiveString, VaultEntry};

/// Import errors
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type ImportResult<T> = Result<T, ImportError>;

/// Import format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    VaulticEncrypted,
    BitwardenJson,
    LastPassCsv,
    OnePasswordCsv,
}

/// Import entries from encrypted Vaultic backup
pub fn import_encrypted(data: &[u8], master_key: &MasterKey) -> ImportResult<Vec<VaultEntry>> {
    let backup: EncryptedBackup = bincode::deserialize(data)
        .map_err(|e| ImportError::Parse(format!("Invalid backup format: {}", e)))?;

    let derived = master_key.derive_keys();
    let cipher = Cipher::new(&derived.encryption_key);
    let decrypted = cipher.decrypt(&backup.encrypted_data)?;

    bincode::deserialize(&decrypted)
        .map_err(|e| ImportError::Parse(format!("Failed to deserialize entries: {}", e)))
}

/// Bitwarden JSON format
#[derive(Debug, Deserialize)]
struct BitwardenExport {
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    name: String,
    #[serde(rename = "type")]
    item_type: u32,
    login: Option<BitwardenLogin>,
    notes: Option<String>,
    #[serde(rename = "folderId")]
    #[allow(dead_code)]
    folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<BitwardenUri>>,
    totp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

/// Import entries from Bitwarden JSON export
pub fn import_bitwarden(json: &str) -> ImportResult<Vec<VaultEntry>> {
    let export: BitwardenExport = serde_json::from_str(json)
        .map_err(|e| ImportError::Parse(format!("Invalid Bitwarden JSON: {}", e)))?;

    let entries = export
        .items
        .into_iter()
        .filter(|item| item.item_type == 1) // Only login items
        .map(|item| {
            let mut entry = VaultEntry::new(&item.name, EntryType::Password);
            if let Some(login) = item.login {
                if let Some(u) = login.username {
                    entry.username = Some(u);
                }
                if let Some(p) = login.password {
                    entry.password = Some(SensitiveString::new(p));
                }
                if let Some(uris) = login.uris {
                    if let Some(uri) = uris.first().and_then(|u| u.uri.clone()) {
                        entry.url = Some(uri);
                    }
                }
                if let Some(totp) = login.totp {
                    entry.totp_secret = Some(SensitiveString::new(totp));
                }
            }
            if let Some(notes) = item.notes {
                entry.notes = Some(SensitiveString::new(notes));
            }
            entry
        })
        .collect();

    Ok(entries)
}

/// Import entries from LastPass CSV export
pub fn import_lastpass(csv: &str) -> ImportResult<Vec<VaultEntry>> {
    let mut entries = Vec::new();
    let mut lines = csv.lines();

    // Skip header: url,username,password,name,grouping,fav
    lines.next();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = parse_csv_line(line);
        if fields.len() >= 4 {
            let mut entry = VaultEntry::new(fields[3], EntryType::Password);
            if !fields[0].is_empty() {
                entry.url = Some(fields[0].to_string());
            }
            if !fields[1].is_empty() {
                entry.username = Some(fields[1].to_string());
            }
            if !fields[2].is_empty() {
                entry.password = Some(SensitiveString::new(fields[2].to_string()));
            }
            if fields.len() > 4 && !fields[4].is_empty() {
                entry.folder = Some(fields[4].to_string());
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Import entries from 1Password CSV export
pub fn import_1password(csv: &str) -> ImportResult<Vec<VaultEntry>> {
    let mut entries = Vec::new();
    let mut lines = csv.lines();

    // Skip header: Title,Username,Password,URL,Notes
    lines.next();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = parse_csv_line(line);
        if fields.len() >= 3 {
            let mut entry = VaultEntry::new(fields[0], EntryType::Password);
            if !fields[1].is_empty() {
                entry.username = Some(fields[1].to_string());
            }
            if !fields[2].is_empty() {
                entry.password = Some(SensitiveString::new(fields[2].to_string()));
            }
            if fields.len() > 3 && !fields[3].is_empty() {
                entry.url = Some(fields[3].to_string());
            }
            if fields.len() > 4 && !fields[4].is_empty() {
                entry.notes = Some(SensitiveString::new(fields[4].to_string()));
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;

    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(line[start..i].trim_matches('"'));
                start = i + 1;
            }
            _ => {}
        }
    }
    fields.push(line[start..].trim_matches('"'));
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_bitwarden() {
        let json =
            r#"{"items":[{"name":"Test","type":1,"login":{"username":"user","password":"pass"}}]}"#;
        let entries = import_bitwarden(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Test");
        assert_eq!(entries[0].username, Some("user".to_string()));
    }

    #[test]
    fn test_import_lastpass() {
        let csv = "url,username,password,name,grouping,fav\nhttps://test.com,user,pass,Test,,0\n";
        let entries = import_lastpass(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Test");
    }

    #[test]
    fn test_import_1password() {
        let csv = "Title,Username,Password,URL,Notes\nTest,user,pass,https://test.com,\n";
        let entries = import_1password(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Test");
    }
}
