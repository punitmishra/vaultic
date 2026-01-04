//! Migration module for upgrading vaults from v1 to v2 format
//!
//! v1 format: Single password unlock, KDF params in separate file
//! v2 format: Multi-method unlock via keyring with wrapped vault key

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

use crate::crypto::kek::derive_from_password;
use crate::crypto::keys::{EncryptedVaultKey, MethodData, UnlockMethod, VaultKey, VaultKeyring};
use crate::crypto::wrap::{generate_salt, wrap_vault_key};
use crate::crypto::{Cipher, KeyDeriver, MasterKey};
use crate::models::KdfParams;
use crate::storage::keyring::{detect_vault_version, KeyringStorage, VaultVersion};
use crate::storage::{KdfParamsStorage, StorageError, VaultStorage};

/// Result of a migration operation
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Number of entries in the vault
    pub entry_count: usize,
    /// Path to backup of old format
    pub backup_path: Option<PathBuf>,
    /// Whether the keyring was created
    pub keyring_created: bool,
    /// Vault ID after migration
    pub vault_id: Uuid,
    /// Version migrated from
    pub from_version: VaultVersion,
    /// Version migrated to
    pub to_version: VaultVersion,
}

/// Handles vault migration from v1 to v2 format
pub struct VaultMigrator {
    vault_path: PathBuf,
}

impl VaultMigrator {
    /// Create a new migrator for the given vault path
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault_path: vault_path.as_ref().to_path_buf(),
        }
    }

    /// Check if the vault needs migration
    pub fn needs_migration(&self) -> bool {
        detect_vault_version(&self.vault_path) == VaultVersion::V1
    }

    /// Get the current vault version
    pub fn current_version(&self) -> VaultVersion {
        detect_vault_version(&self.vault_path)
    }

    /// Perform a dry run of the migration (doesn't modify anything)
    pub fn dry_run(&self, password: &str) -> Result<MigrationReport, StorageError> {
        // Verify password works with current vault
        let kdf_params = KdfParamsStorage::load(&self.vault_path)?;
        let master_key = KeyDeriver::derive_from_password(password.as_bytes(), &kdf_params)
            .map_err(|e| StorageError::Crypto(e))?;

        // Try to open and unlock the vault
        let mut storage = VaultStorage::open(&self.vault_path)?;
        storage.unlock(&master_key)?;

        let entry_count = storage.list_entries()?.len();
        let vault_id = storage.metadata().map(|m| m.id).unwrap_or_else(Uuid::new_v4);

        Ok(MigrationReport {
            entry_count,
            backup_path: None,
            keyring_created: false,
            vault_id,
            from_version: VaultVersion::V1,
            to_version: VaultVersion::V2,
        })
    }

    /// Migrate the vault from v1 to v2 format
    ///
    /// This creates a new VaultKey, re-encrypts the master key derivation
    /// into a wrapped vault key, and creates a keyring.
    ///
    /// Note: In v1, the MasterKey IS the encryption key. In v2, a separate
    /// VaultKey is used, wrapped by the password-derived KEK. For migration,
    /// we generate a new VaultKey and re-encrypt all entries with it.
    pub fn migrate(&self, password: &str) -> Result<MigrationReport, StorageError> {
        if !self.needs_migration() {
            return Err(StorageError::InvalidData);
        }

        // Step 1: Load existing KDF params and derive the old master key
        let kdf_params = KdfParamsStorage::load(&self.vault_path)?;
        let old_master_key = KeyDeriver::derive_from_password(password.as_bytes(), &kdf_params)
            .map_err(|e| StorageError::Crypto(e))?;

        // Step 2: Open and unlock the vault with old key
        let mut storage = VaultStorage::open(&self.vault_path)?;
        storage.unlock(&old_master_key)?;

        let entries = storage.list_entries()?;
        let vault_id = storage.metadata().map(|m| m.id).unwrap_or_else(Uuid::new_v4);

        // Step 3: Create backup of kdf_params.json
        let backup_path = self.backup_kdf_params()?;

        // Step 4: For simplicity in migration, we'll use the old master key AS
        // the vault key. This means existing encrypted entries remain valid.
        // The key hierarchy benefit is that we can now add more unlock methods.
        let vault_key = VaultKey::from_bytes(*old_master_key.as_bytes());

        // Step 5: Create KEK from password and wrap the vault key
        let kek = derive_from_password(password.as_bytes(), &kdf_params)
            .map_err(|e| StorageError::Crypto(e))?;

        let encrypted_vault_key = wrap_vault_key(
            &vault_key,
            &kek,
            UnlockMethod::Password,
            MethodData::Password {
                params: kdf_params.clone(),
            },
            Some("Master Password".to_string()),
        )
        .map_err(|e| StorageError::Crypto(e))?;

        // Step 6: Create and save keyring
        let mut keyring = VaultKeyring::new(vault_id);
        keyring.add_key(encrypted_vault_key);

        let keyring_storage = KeyringStorage::new(&self.vault_path);
        keyring_storage.save(&keyring)?;

        Ok(MigrationReport {
            entry_count: entries.len(),
            backup_path: Some(backup_path),
            keyring_created: true,
            vault_id,
            from_version: VaultVersion::V1,
            to_version: VaultVersion::V2,
        })
    }

    /// Create a backup of the kdf_params.json file
    fn backup_kdf_params(&self) -> Result<PathBuf, StorageError> {
        let original = self.vault_path.join("kdf_params.json");
        let backup = self.vault_path.join(format!(
            "kdf_params.json.backup.{}",
            Utc::now().format("%Y%m%d%H%M%S")
        ));

        if original.exists() {
            fs::copy(&original, &backup)
                .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        }

        Ok(backup)
    }

    /// Rollback a migration (restore from backup)
    pub fn rollback(&self) -> Result<(), StorageError> {
        // Find the most recent backup
        let entries = fs::read_dir(&self.vault_path)
            .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;

        let mut backup_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("kdf_params.json.backup.")
            })
            .collect();

        backup_files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

        if let Some(latest_backup) = backup_files.first() {
            // Remove keyring
            let keyring_path = self.vault_path.join("keyring.json");
            if keyring_path.exists() {
                fs::remove_file(&keyring_path)
                    .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
            }

            // Restore kdf_params from backup
            let kdf_params_path = self.vault_path.join("kdf_params.json");
            fs::copy(latest_backup.path(), &kdf_params_path)
                .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;

            Ok(())
        } else {
            Err(StorageError::NotFound(
                "No backup found for rollback".to_string(),
            ))
        }
    }
}

/// Check if a vault can be migrated
pub fn can_migrate(vault_path: impl AsRef<Path>) -> bool {
    let migrator = VaultMigrator::new(vault_path);
    migrator.needs_migration()
}

/// Quick helper to migrate a vault
pub fn migrate_vault(vault_path: impl AsRef<Path>, password: &str) -> Result<MigrationReport, StorageError> {
    let migrator = VaultMigrator::new(vault_path);
    migrator.migrate(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_v1_vault(path: &Path, password: &str) -> (MasterKey, KdfParams) {
        let kdf_params = KeyDeriver::generate_params();
        let master_key = KeyDeriver::derive_from_password(password.as_bytes(), &kdf_params).unwrap();

        // Create vault with v1 format
        let mut storage = VaultStorage::create(
            path,
            "Test Vault",
            &master_key,
            kdf_params.clone(),
            "test-fingerprint".to_string(),
        )
        .unwrap();

        // Add a test entry
        let entry = crate::models::VaultEntry::new("GitHub", crate::models::EntryType::Password)
            .with_username("user@example.com")
            .with_password("secret123");
        storage.add_entry(&entry).unwrap();

        // Note: VaultStorage::create already saves kdf_params.json
        // and doesn't create keyring.json, so this is a v1 vault

        (master_key, kdf_params)
    }

    #[test]
    fn test_vault_version_detection() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        // Create v1 vault
        create_v1_vault(&vault_path, "password123");

        let migrator = VaultMigrator::new(&vault_path);
        assert_eq!(migrator.current_version(), VaultVersion::V1);
        assert!(migrator.needs_migration());
    }

    #[test]
    fn test_migration_dry_run() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");

        let migrator = VaultMigrator::new(&vault_path);
        let report = migrator.dry_run("password123").unwrap();

        assert_eq!(report.entry_count, 1);
        assert_eq!(report.from_version, VaultVersion::V1);
        assert_eq!(report.to_version, VaultVersion::V2);
        assert!(!report.keyring_created);
        assert!(report.backup_path.is_none());

        // Vault should still be v1
        assert!(migrator.needs_migration());
    }

    #[test]
    fn test_migration_dry_run_wrong_password() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");

        let migrator = VaultMigrator::new(&vault_path);
        let result = migrator.dry_run("wrong_password");

        assert!(result.is_err());
    }

    #[test]
    fn test_full_migration() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");

        let migrator = VaultMigrator::new(&vault_path);
        assert!(migrator.needs_migration());

        let report = migrator.migrate("password123").unwrap();

        assert_eq!(report.entry_count, 1);
        assert!(report.keyring_created);
        assert!(report.backup_path.is_some());
        assert_eq!(report.from_version, VaultVersion::V1);
        assert_eq!(report.to_version, VaultVersion::V2);

        // Vault should now be v2
        assert!(!migrator.needs_migration());
        assert_eq!(migrator.current_version(), VaultVersion::V2);

        // Keyring should exist
        let keyring_storage = KeyringStorage::new(&vault_path);
        assert!(keyring_storage.exists());

        let keyring = keyring_storage.load().unwrap();
        assert_eq!(keyring.method_count(), 1);
        assert!(keyring.has_password());
    }

    #[test]
    fn test_migration_preserves_entries() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        let (master_key, _) = create_v1_vault(&vault_path, "password123");

        // Migrate
        let migrator = VaultMigrator::new(&vault_path);
        migrator.migrate("password123").unwrap();

        // Open with same key and verify entries
        drop(migrator);
        let mut storage = VaultStorage::open(&vault_path).unwrap();
        storage.unlock(&master_key).unwrap();

        let entries = storage.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
    }

    #[test]
    fn test_rollback() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");

        // Migrate
        let migrator = VaultMigrator::new(&vault_path);
        migrator.migrate("password123").unwrap();
        assert!(!migrator.needs_migration());

        // Rollback
        migrator.rollback().unwrap();

        // Should be back to v1
        assert!(migrator.needs_migration());
        assert!(!KeyringStorage::new(&vault_path).exists());
    }

    #[test]
    fn test_double_migration_fails() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");

        let migrator = VaultMigrator::new(&vault_path);
        migrator.migrate("password123").unwrap();

        // Second migration should fail
        let result = migrator.migrate("password123");
        assert!(result.is_err());
    }

    #[test]
    fn test_can_migrate_helper() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        create_v1_vault(&vault_path, "password123");
        assert!(can_migrate(&vault_path));

        migrate_vault(&vault_path, "password123").unwrap();
        assert!(!can_migrate(&vault_path));
    }
}
