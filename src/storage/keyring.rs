//! Keyring persistence for multi-method unlock
//!
//! This module handles saving and loading the VaultKeyring, which contains
//! all encrypted vault keys for different unlock methods.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::keys::VaultKeyring;

use super::StorageError;

/// Manages keyring file storage
pub struct KeyringStorage {
    path: PathBuf,
}

impl KeyringStorage {
    /// Keyring filename (stored in vault directory)
    const FILENAME: &'static str = "keyring.json";

    /// Create a new KeyringStorage for the given vault path
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            path: vault_path.as_ref().join(Self::FILENAME),
        }
    }

    /// Check if a keyring exists at this path
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Get the keyring file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save a keyring to disk
    ///
    /// The keyring itself is not encrypted (the vault keys inside are),
    /// but we use pretty JSON for easier debugging and version control.
    pub fn save(&self, keyring: &VaultKeyring) -> Result<(), StorageError> {
        let json = serde_json::to_string_pretty(keyring).map_err(|e| {
            StorageError::Serialization(bincode::Error::from(bincode::ErrorKind::Custom(
                e.to_string(),
            )))
        })?;

        // Create parent directories if they don't exist
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        }

        // Write atomically using a temp file
        let temp_path = self.path.with_extension("json.tmp");
        fs::write(&temp_path, &json).map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        fs::rename(&temp_path, &self.path)
            .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;

        Ok(())
    }

    /// Load a keyring from disk
    pub fn load(&self) -> Result<VaultKeyring, StorageError> {
        let json = fs::read_to_string(&self.path)
            .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;

        let keyring: VaultKeyring = serde_json::from_str(&json).map_err(|e| {
            StorageError::Serialization(bincode::Error::from(bincode::ErrorKind::Custom(
                e.to_string(),
            )))
        })?;

        Ok(keyring)
    }

    /// Delete the keyring file (for vault reset)
    pub fn delete(&self) -> Result<(), StorageError> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        }
        Ok(())
    }

    /// Create a backup of the keyring
    pub fn backup(&self) -> Result<PathBuf, StorageError> {
        if !self.exists() {
            return Err(StorageError::NotFound("Keyring not found".to_string()));
        }

        let backup_path = self.path.with_extension(format!(
            "json.backup.{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ));

        fs::copy(&self.path, &backup_path)
            .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;

        Ok(backup_path)
    }
}

/// Check if a vault uses the v2 keyring format
pub fn has_v2_keyring(vault_path: impl AsRef<Path>) -> bool {
    KeyringStorage::new(vault_path).exists()
}

/// Check if a vault uses the v1 format (only kdf_params.json, no keyring.json)
pub fn is_v1_vault(vault_path: impl AsRef<Path>) -> bool {
    let vault_path = vault_path.as_ref();
    let has_kdf_params = vault_path.join("kdf_params.json").exists();
    let has_keyring = vault_path.join("keyring.json").exists();

    has_kdf_params && !has_keyring
}

/// Determine the vault version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultVersion {
    /// Original format with single password unlock
    V1,
    /// New format with multi-method unlock via keyring
    V2,
    /// Not a valid vault directory
    Unknown,
}

/// Detect the version of a vault
pub fn detect_vault_version(vault_path: impl AsRef<Path>) -> VaultVersion {
    let vault_path = vault_path.as_ref();

    if has_v2_keyring(vault_path) {
        VaultVersion::V2
    } else if is_v1_vault(vault_path) {
        VaultVersion::V1
    } else {
        VaultVersion::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{EncryptedVaultKey, MethodData, UnlockMethod};
    use crate::models::KdfParams;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn create_test_keyring() -> VaultKeyring {
        let mut keyring = VaultKeyring::new(Uuid::new_v4());

        let encrypted = EncryptedVaultKey::new(
            UnlockMethod::Password,
            vec![0; 48],
            [0; 24],
            MethodData::Password {
                params: KdfParams::default(),
            },
            Some("Test Password".to_string()),
        );
        keyring.add_key(encrypted);

        keyring
    }

    #[test]
    fn test_keyring_save_load() {
        let dir = tempdir().unwrap();
        let storage = KeyringStorage::new(dir.path());

        let keyring = create_test_keyring();
        storage.save(&keyring).unwrap();

        assert!(storage.exists());

        let loaded = storage.load().unwrap();
        assert_eq!(loaded.vault_id, keyring.vault_id);
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].method, UnlockMethod::Password);
    }

    #[test]
    fn test_keyring_backup() {
        let dir = tempdir().unwrap();
        let storage = KeyringStorage::new(dir.path());

        let keyring = create_test_keyring();
        storage.save(&keyring).unwrap();

        let backup_path = storage.backup().unwrap();
        assert!(backup_path.exists());
        assert!(backup_path.to_string_lossy().contains(".backup."));
    }

    #[test]
    fn test_keyring_delete() {
        let dir = tempdir().unwrap();
        let storage = KeyringStorage::new(dir.path());

        let keyring = create_test_keyring();
        storage.save(&keyring).unwrap();
        assert!(storage.exists());

        storage.delete().unwrap();
        assert!(!storage.exists());
    }

    #[test]
    fn test_vault_version_detection() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();

        // Empty directory = Unknown
        assert_eq!(detect_vault_version(vault_path), VaultVersion::Unknown);

        // Only kdf_params.json = V1
        fs::write(vault_path.join("kdf_params.json"), "{}").unwrap();
        assert_eq!(detect_vault_version(vault_path), VaultVersion::V1);

        // Add keyring.json = V2
        fs::write(vault_path.join("keyring.json"), "{}").unwrap();
        assert_eq!(detect_vault_version(vault_path), VaultVersion::V2);
    }

    #[test]
    fn test_is_v1_vault() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();

        // Empty = not v1
        assert!(!is_v1_vault(vault_path));

        // Only kdf_params = v1
        fs::write(vault_path.join("kdf_params.json"), "{}").unwrap();
        assert!(is_v1_vault(vault_path));

        // With keyring = not v1
        fs::write(vault_path.join("keyring.json"), "{}").unwrap();
        assert!(!is_v1_vault(vault_path));
    }

    #[test]
    fn test_has_v2_keyring() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path();

        assert!(!has_v2_keyring(vault_path));

        fs::write(vault_path.join("keyring.json"), "{}").unwrap();
        assert!(has_v2_keyring(vault_path));
    }

    #[test]
    fn test_keyring_path() {
        let dir = tempdir().unwrap();
        let storage = KeyringStorage::new(dir.path());

        assert_eq!(storage.path(), dir.path().join("keyring.json"));
    }
}
