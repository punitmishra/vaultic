//! Encrypted storage layer for Vaultic
//!
//! This module provides persistent, encrypted storage for vault entries using
//! the sled embedded database. All data is encrypted at rest using the master key.
//!
//! # Features
//!
//! - **Encryption at rest**: All entries encrypted with XChaCha20-Poly1305
//! - **CRUD operations**: Create, read, update, delete entries
//! - **Search**: Filter by name, tags, folder, type, and more
//! - **Atomic operations**: Transactional updates via sled
//! - **Multi-method unlock**: Keyring storage for v2 vaults
//!
//! # Storage Layout
//!
//! ## V1 (Legacy)
//! ```text
//! vault_path/
//! ├── db/              # Sled database files
//! ├── kdf_params.json  # Key derivation parameters (unencrypted)
//! └── session/         # Session files (encrypted)
//! ```
//!
//! ## V2 (Multi-method unlock)
//! ```text
//! vault_path/
//! ├── db/              # Sled database files
//! ├── keyring.json     # Encrypted vault keys for each unlock method
//! ├── kdf_params.json  # Key derivation parameters (for password method)
//! └── session/         # Session files (encrypted)
//! ```
//!
//! # Example
//!
//! ```no_run
//! use vaultic::storage::VaultStorage;
//! use vaultic::models::{VaultEntry, EntryType};
//! use vaultic::crypto::MasterKey;
//!
//! // Open vault
//! let mut storage = VaultStorage::open("/path/to/vault").unwrap();
//!
//! // Unlock with master key
//! let key = MasterKey::from_bytes([0u8; 32]);
//! storage.unlock(&key).unwrap();
//!
//! // Add entry
//! let entry = VaultEntry::new("GitHub", EntryType::Password);
//! storage.add_entry(&entry).unwrap();
//! ```

pub mod keyring;

use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};
use sled::{Db, Tree};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{Cipher, CryptoError, IdentityKeyPair, KeyDeriver, MasterKey};
use crate::models::{
    AuditLogEntry, KdfParams, SearchFilter, SharedSecret, UserIdentity, VaultEntry, VaultMetadata,
};

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Entry not found: {0}")]
    NotFound(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault already exists")]
    VaultAlreadyExists,

    #[error("Invalid vault data")]
    InvalidData,
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Tree names for different data types
mod trees {
    pub const METADATA: &str = "metadata";
    pub const ENTRIES: &str = "entries";
    pub const IDENTITIES: &str = "identities";
    pub const SHARED_SECRETS: &str = "shared_secrets";
    pub const AUDIT_LOG: &str = "audit_log";
    pub const CONFIG: &str = "config";
    pub const OWN_KEYPAIR: &str = "own_keypair";
}

/// Encrypted vault storage
pub struct VaultStorage {
    db: Db,
    #[allow(dead_code)]
    path: PathBuf,
    cipher: Option<Cipher>,
    metadata: Option<VaultMetadata>,
}

impl VaultStorage {
    /// Open or create a vault at the given path
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let db = sled::open(&path)?;

        Ok(Self {
            db,
            path,
            cipher: None,
            metadata: None,
        })
    }

    /// Create a new vault with the given master key
    pub fn create(
        path: impl AsRef<Path>,
        name: impl Into<String>,
        master_key: &MasterKey,
        kdf_params: KdfParams,
        owner_fingerprint: String,
    ) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();

        if path.exists() {
            return Err(StorageError::VaultAlreadyExists);
        }

        let db = sled::open(&path)?;
        let derived = master_key.derive_keys();
        let cipher = Cipher::new(&derived.encryption_key);

        let metadata = VaultMetadata {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            version: 1,
            entry_count: 0,
            owner_fingerprint,
            encryption_algo: "xchacha20poly1305".to_string(),
            kdf_params,
        };

        let storage = Self {
            db,
            path: path.clone(),
            cipher: Some(cipher),
            metadata: Some(metadata.clone()),
        };

        storage.save_metadata(&metadata)?;

        // Save KDF params separately (unencrypted) so we can load them during unlock
        KdfParamsStorage::save(&path, &metadata.kdf_params)?;

        Ok(storage)
    }

    /// Unlock the vault with a master key
    pub fn unlock(&mut self, master_key: &MasterKey) -> StorageResult<()> {
        let derived = master_key.derive_keys();
        let cipher = Cipher::new(&derived.encryption_key);

        // Try to decrypt metadata to verify key
        let metadata = self.load_metadata(&cipher)?;

        self.cipher = Some(cipher);
        self.metadata = Some(metadata);

        Ok(())
    }

    /// Derive the master key for this (already-open) vault from a password and
    /// leave the vault unlocked, transparently handling legacy vaults.
    ///
    /// The honest derivation over the recorded KDF parameters is tried first;
    /// if it fails to unlock, the pre-2.3 legacy derivation
    /// ([`KeyDeriver::derive_legacy_default`]) is tried as a fallback. Returns
    /// the working master key together with a flag that is `true` when the
    /// legacy fallback was the one that succeeded — a signal that the on-disk
    /// KDF metadata is lying and can be self-healed via
    /// [`heal_legacy_kdf_params`](Self::heal_legacy_kdf_params). When both
    /// derivations fail (a genuinely wrong password), the honest attempt's
    /// error is returned. Does not modify anything on disk.
    pub fn unlock_with_password_ext(
        &mut self,
        password: &[u8],
    ) -> StorageResult<(MasterKey, bool)> {
        let params = KdfParamsStorage::load(&self.path)?;

        let honest =
            KeyDeriver::derive_from_password(password, &params).map_err(StorageError::Crypto)?;
        match self.unlock(&honest) {
            Ok(()) => Ok((honest, false)),
            Err(honest_err) => {
                // Legacy fallback: pre-2.3 CLI vaults derived the master key
                // with `Argon2::default()`, ignoring the recorded parameters.
                let legacy = KeyDeriver::derive_legacy_default(password, &params.salt)
                    .map_err(StorageError::Crypto)?;
                match self.unlock(&legacy) {
                    Ok(()) => Ok((legacy, true)),
                    // Neither key worked: surface the honest error, since that
                    // is the derivation the vault is expected to use.
                    Err(_) => Err(honest_err),
                }
            }
        }
    }

    /// Rewrite `kdf_params.json` so it records the *true* Argon2-default
    /// parameters, correcting a legacy vault whose stored metadata lies about
    /// the parameters that were actually applied.
    ///
    /// This is metadata-only: the vault key is unchanged, so no entries are
    /// re-encrypted. Afterwards the honest [`KeyDeriver::derive_from_password`]
    /// derivation reproduces the same key, which restores CLI↔GUI/agent interop
    /// (the daemon and GUI always honor the stored parameters) and makes
    /// subsequent unlocks single-derivation.
    pub fn heal_legacy_kdf_params(&self) -> StorageResult<()> {
        let params = KdfParamsStorage::load(&self.path)?;
        let healed = KeyDeriver::legacy_default_params(params.salt);
        KdfParamsStorage::save(&self.path, &healed)
    }

    /// Lock the vault (clear cipher and metadata from memory)
    pub fn lock(&mut self) {
        self.cipher = None;
        self.metadata = None;
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.cipher.is_some()
    }

    fn get_cipher(&self) -> StorageResult<&Cipher> {
        self.cipher.as_ref().ok_or(StorageError::VaultLocked)
    }

    fn get_tree(&self, name: &str) -> StorageResult<Tree> {
        Ok(self.db.open_tree(name)?)
    }

    /// Encrypt and store data
    fn store_encrypted<T: Serialize>(
        &self,
        tree: &Tree,
        key: &[u8],
        value: &T,
    ) -> StorageResult<()> {
        let cipher = self.get_cipher()?;
        let serialized = bincode::serialize(value)?;
        let encrypted = cipher.encrypt(&serialized)?;
        tree.insert(key, encrypted)?;
        Ok(())
    }

    /// Load and decrypt data
    fn load_encrypted<T: DeserializeOwned>(
        &self,
        tree: &Tree,
        key: &[u8],
    ) -> StorageResult<Option<T>> {
        let cipher = self.get_cipher()?;

        if let Some(encrypted) = tree.get(key)? {
            let decrypted = cipher.decrypt(&encrypted)?;
            let value = bincode::deserialize(&decrypted)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Load metadata (used during unlock)
    fn load_metadata(&self, cipher: &Cipher) -> StorageResult<VaultMetadata> {
        let tree = self.get_tree(trees::METADATA)?;

        if let Some(encrypted) = tree.get(b"vault_metadata")? {
            let decrypted = cipher.decrypt(&encrypted)?;
            let metadata = bincode::deserialize(&decrypted)?;
            Ok(metadata)
        } else {
            Err(StorageError::InvalidData)
        }
    }

    /// Save metadata
    fn save_metadata(&self, metadata: &VaultMetadata) -> StorageResult<()> {
        let tree = self.get_tree(trees::METADATA)?;
        self.store_encrypted(&tree, b"vault_metadata", metadata)
    }

    /// Get vault metadata
    pub fn metadata(&self) -> Option<&VaultMetadata> {
        self.metadata.as_ref()
    }

    // ============ Entry Operations ============

    /// Add a new entry
    pub fn add_entry(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        let tree = self.get_tree(trees::ENTRIES)?;
        self.store_encrypted(&tree, entry.id.as_bytes(), entry)?;

        // Update entry count
        if let Some(ref mut metadata) = self.metadata {
            metadata.entry_count += 1;
            metadata.updated_at = chrono::Utc::now();
            let updated = metadata.clone();
            self.save_metadata(&updated)?;
        }

        Ok(())
    }

    /// Get an entry by ID
    pub fn get_entry(&self, id: &Uuid) -> StorageResult<Option<VaultEntry>> {
        let tree = self.get_tree(trees::ENTRIES)?;
        self.load_encrypted(&tree, id.as_bytes())
    }

    /// Update an entry
    pub fn update_entry(&self, entry: &VaultEntry) -> StorageResult<()> {
        let tree = self.get_tree(trees::ENTRIES)?;

        // Verify entry exists
        if tree.get(entry.id.as_bytes())?.is_none() {
            return Err(StorageError::NotFound(entry.id.to_string()));
        }

        self.store_encrypted(&tree, entry.id.as_bytes(), entry)?;

        if let Some(ref metadata) = self.metadata {
            let mut updated = metadata.clone();
            updated.updated_at = chrono::Utc::now();
            self.save_metadata(&updated)?;
        }

        Ok(())
    }

    /// Delete an entry
    pub fn delete_entry(&mut self, id: &Uuid) -> StorageResult<()> {
        let tree = self.get_tree(trees::ENTRIES)?;

        if tree.remove(id.as_bytes())?.is_none() {
            return Err(StorageError::NotFound(id.to_string()));
        }

        if let Some(ref mut metadata) = self.metadata {
            metadata.entry_count = metadata.entry_count.saturating_sub(1);
            metadata.updated_at = chrono::Utc::now();
            let updated = metadata.clone();
            self.save_metadata(&updated)?;
        }

        Ok(())
    }

    /// List all entries
    pub fn list_entries(&self) -> StorageResult<Vec<VaultEntry>> {
        let tree = self.get_tree(trees::ENTRIES)?;
        let cipher = self.get_cipher()?;
        // Sized to exactly tree.len() so the Vec never reallocates as we
        // push decrypted entries. sled::Tree::len iterates keys (O(n)) but
        // doesn't decrypt; the saving from skipping doubling-reallocation
        // of large VaultEntry values dominates that cost on real vaults.
        // Verified via benches/vault_ops.rs.
        let mut entries = Vec::with_capacity(tree.len());

        for result in tree.iter() {
            let (_, encrypted) = result?;
            let decrypted = cipher.decrypt(&encrypted)?;
            let entry: VaultEntry = bincode::deserialize(&decrypted)?;
            entries.push(entry);
        }

        // Sort by name. Cache the lowercased key so we don't allocate
        // a fresh String per comparison.
        entries.sort_by_cached_key(|e| e.name.to_lowercase());
        Ok(entries)
    }

    /// Search entries with filter
    pub fn search_entries(&self, filter: &SearchFilter) -> StorageResult<Vec<VaultEntry>> {
        use fuzzy_matcher::FuzzyMatcher;
        let all_entries = self.list_entries()?;
        let matcher = fuzzy_matcher::skim::SkimMatcherV2::default();

        let filtered: Vec<VaultEntry> = all_entries
            .into_iter()
            .filter(|entry| {
                // Query filter (fuzzy)
                if let Some(ref query) = filter.query {
                    let query_lower = query.to_lowercase();
                    let matches_name = matcher
                        .fuzzy_match(&entry.name.to_lowercase(), &query_lower)
                        .is_some();
                    let matches_username = entry
                        .username
                        .as_ref()
                        .map(|u| {
                            matcher
                                .fuzzy_match(&u.to_lowercase(), &query_lower)
                                .is_some()
                        })
                        .unwrap_or(false);
                    let matches_url = entry
                        .url
                        .as_ref()
                        .map(|u| {
                            matcher
                                .fuzzy_match(&u.to_lowercase(), &query_lower)
                                .is_some()
                        })
                        .unwrap_or(false);
                    let matches_tags = entry.tags.iter().any(|t| {
                        matcher
                            .fuzzy_match(&t.to_lowercase(), &query_lower)
                            .is_some()
                    });

                    if !(matches_name || matches_username || matches_url || matches_tags) {
                        return false;
                    }
                }

                // Entry type filter
                if let Some(ref entry_type) = filter.entry_type {
                    if &entry.entry_type != entry_type {
                        return false;
                    }
                }

                // Tags filter
                if !filter.tags.is_empty() {
                    let has_all_tags = filter.tags.iter().all(|t| entry.tags.contains(t));
                    if !has_all_tags {
                        return false;
                    }
                }

                // Folder filter
                if let Some(ref folder) = filter.folder {
                    if entry.folder.as_ref() != Some(folder) {
                        return false;
                    }
                }

                // Favorites filter
                if filter.favorites_only && !entry.favorite {
                    return false;
                }

                // Needs rotation filter
                if filter.needs_rotation && !entry.needs_rotation() {
                    return false;
                }

                // Weak passwords filter
                if filter.weak_passwords {
                    use crate::models::PasswordStrength;
                    let is_weak = entry
                        .password_strength
                        .as_ref()
                        .map(|s| *s <= PasswordStrength::Weak)
                        .unwrap_or(false);
                    if !is_weak {
                        return false;
                    }
                }

                true
            })
            .skip(filter.offset)
            .take(filter.limit.unwrap_or(usize::MAX))
            .collect();

        Ok(filtered)
    }

    // ============ Identity Operations ============

    /// Add a user identity (for sharing)
    pub fn add_identity(&self, identity: &UserIdentity) -> StorageResult<()> {
        let tree = self.get_tree(trees::IDENTITIES)?;
        self.store_encrypted(&tree, identity.id.as_bytes(), identity)
    }

    /// Get identity by ID
    pub fn get_identity(&self, id: &Uuid) -> StorageResult<Option<UserIdentity>> {
        let tree = self.get_tree(trees::IDENTITIES)?;
        self.load_encrypted(&tree, id.as_bytes())
    }

    /// Get identity by fingerprint
    pub fn get_identity_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> StorageResult<Option<UserIdentity>> {
        let tree = self.get_tree(trees::IDENTITIES)?;
        let cipher = self.get_cipher()?;

        for result in tree.iter() {
            let (_, encrypted) = result?;
            let decrypted = cipher.decrypt(&encrypted)?;
            let identity: UserIdentity = bincode::deserialize(&decrypted)?;
            if identity.fingerprint == fingerprint {
                return Ok(Some(identity));
            }
        }

        Ok(None)
    }

    /// List all identities
    pub fn list_identities(&self) -> StorageResult<Vec<UserIdentity>> {
        let tree = self.get_tree(trees::IDENTITIES)?;
        let cipher = self.get_cipher()?;
        let mut identities = Vec::new();

        for result in tree.iter() {
            let (_, encrypted) = result?;
            let decrypted = cipher.decrypt(&encrypted)?;
            let identity: UserIdentity = bincode::deserialize(&decrypted)?;
            identities.push(identity);
        }

        Ok(identities)
    }

    // ============ Shared Secrets ============

    /// Store a shared secret
    pub fn add_shared_secret(&self, secret: &SharedSecret) -> StorageResult<()> {
        let tree = self.get_tree(trees::SHARED_SECRETS)?;
        self.store_encrypted(&tree, secret.id.as_bytes(), secret)
    }

    /// Get shared secrets for an entry
    pub fn get_shared_secrets_for_entry(
        &self,
        entry_id: &Uuid,
    ) -> StorageResult<Vec<SharedSecret>> {
        let tree = self.get_tree(trees::SHARED_SECRETS)?;
        let cipher = self.get_cipher()?;
        let mut secrets = Vec::new();

        for result in tree.iter() {
            let (_, encrypted) = result?;
            let decrypted = cipher.decrypt(&encrypted)?;
            let secret: SharedSecret = bincode::deserialize(&decrypted)?;
            if secret.entry_id == *entry_id {
                secrets.push(secret);
            }
        }

        Ok(secrets)
    }

    /// Delete an identity by ID
    pub fn delete_identity(&self, id: &Uuid) -> StorageResult<bool> {
        let tree = self.get_tree(trees::IDENTITIES)?;
        let removed = tree.remove(id.as_bytes())?.is_some();
        Ok(removed)
    }

    // ============ Own Identity Keypair ============

    /// Store the vault's own identity keypair (encrypted)
    pub fn store_own_keypair(&self, keypair: &IdentityKeyPair) -> StorageResult<()> {
        let cipher = self.get_cipher()?;
        let encrypted = keypair.export(cipher)?;
        let tree = self.get_tree(trees::OWN_KEYPAIR)?;
        tree.insert(b"keypair", encrypted)?;
        Ok(())
    }

    /// Retrieve the vault's own identity keypair
    pub fn get_own_keypair(&self) -> StorageResult<Option<IdentityKeyPair>> {
        let tree = self.get_tree(trees::OWN_KEYPAIR)?;
        match tree.get(b"keypair")? {
            Some(encrypted) => {
                let cipher = self.get_cipher()?;
                let keypair = IdentityKeyPair::import(&encrypted, cipher)?;
                Ok(Some(keypair))
            }
            None => Ok(None),
        }
    }

    /// Check if the vault has an identity keypair
    pub fn has_own_keypair(&self) -> StorageResult<bool> {
        let tree = self.get_tree(trees::OWN_KEYPAIR)?;
        Ok(tree.get(b"keypair")?.is_some())
    }

    /// Store the vault owner's name (for identity)
    pub fn store_owner_name(&self, name: &str) -> StorageResult<()> {
        self.set_config("owner_name", name)
    }

    /// Get the vault owner's name
    pub fn get_owner_name(&self) -> StorageResult<Option<String>> {
        self.get_config("owner_name")
    }

    // ============ Audit Log ============

    /// Add an audit log entry
    pub fn log_audit(&self, entry: &AuditLogEntry) -> StorageResult<()> {
        let tree = self.get_tree(trees::AUDIT_LOG)?;
        self.store_encrypted(&tree, entry.id.as_bytes(), entry)
    }

    /// Get recent audit logs
    pub fn get_audit_logs(&self, limit: usize) -> StorageResult<Vec<AuditLogEntry>> {
        let tree = self.get_tree(trees::AUDIT_LOG)?;
        let cipher = self.get_cipher()?;
        let mut logs = Vec::new();

        for result in tree.iter() {
            let (_, encrypted) = result?;
            let decrypted = cipher.decrypt(&encrypted)?;
            let log: AuditLogEntry = bincode::deserialize(&decrypted)?;
            logs.push(log);
        }

        // Sort by timestamp descending.
        logs.sort_by_key(|log| std::cmp::Reverse(log.timestamp));
        logs.truncate(limit);

        Ok(logs)
    }

    // ============ Configuration ============

    /// Store a config value
    pub fn set_config(&self, key: &str, value: &str) -> StorageResult<()> {
        let tree = self.get_tree(trees::CONFIG)?;
        self.store_encrypted(&tree, key.as_bytes(), &value.to_string())
    }

    /// Get a config value
    pub fn get_config(&self, key: &str) -> StorageResult<Option<String>> {
        let tree = self.get_tree(trees::CONFIG)?;
        self.load_encrypted(&tree, key.as_bytes())
    }

    /// Flush all pending writes
    pub fn flush(&self) -> StorageResult<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get database size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    /// Export vault to encrypted backup
    pub fn export_backup(&self) -> StorageResult<Vec<u8>> {
        let entries = self.list_entries()?;
        let identities = self.list_identities()?;
        let metadata = self.metadata.clone().ok_or(StorageError::VaultLocked)?;

        let backup = VaultBackup {
            metadata,
            entries,
            identities,
            version: 1,
        };

        let cipher = self.get_cipher()?;
        let serialized = bincode::serialize(&backup)?;
        let encrypted = cipher.encrypt(&serialized)?;

        Ok(encrypted)
    }

    /// Import from encrypted backup
    pub fn import_backup(&mut self, encrypted: &[u8]) -> StorageResult<usize> {
        let cipher = self.get_cipher()?;
        let decrypted = cipher.decrypt(encrypted)?;
        let backup: VaultBackup = bincode::deserialize(&decrypted)?;

        let count = backup.entries.len();

        for entry in backup.entries {
            self.add_entry(&entry)?;
        }

        for identity in backup.identities {
            self.add_identity(&identity)?;
        }

        Ok(count)
    }
}

/// Vault backup structure
#[derive(Debug, Serialize, serde::Deserialize)]
struct VaultBackup {
    metadata: VaultMetadata,
    entries: Vec<VaultEntry>,
    identities: Vec<UserIdentity>,
    version: u32,
}

/// KDF params storage (stored unencrypted so we can derive the key)
pub struct KdfParamsStorage;

impl KdfParamsStorage {
    const FILENAME: &'static str = "kdf_params.json";

    pub fn save(path: &Path, params: &KdfParams) -> StorageResult<()> {
        let file_path = path.join(Self::FILENAME);
        let json = serde_json::to_string_pretty(params).map_err(|e| {
            StorageError::Serialization(bincode::Error::from(bincode::ErrorKind::Custom(
                e.to_string(),
            )))
        })?;
        std::fs::write(file_path, json).map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        Ok(())
    }

    pub fn load(path: &Path) -> StorageResult<KdfParams> {
        let file_path = path.join(Self::FILENAME);
        let json = std::fs::read_to_string(file_path)
            .map_err(|e| StorageError::Database(sled::Error::Io(e)))?;
        let params: KdfParams = serde_json::from_str(&json).map_err(|e| {
            StorageError::Serialization(bincode::Error::from(bincode::ErrorKind::Custom(
                e.to_string(),
            )))
        })?;
        Ok(params)
    }

    pub fn exists(path: &Path) -> bool {
        path.join(Self::FILENAME).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_create_and_open() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        let master_key = MasterKey::generate();
        let kdf_params = crate::crypto::KeyDeriver::generate_params();

        // Create vault
        let mut storage = VaultStorage::create(
            &vault_path,
            "Test Vault",
            &master_key,
            kdf_params.clone(),
            "test-fingerprint".to_string(),
        )
        .unwrap();

        // Add entry
        let entry = VaultEntry::new("GitHub", crate::models::EntryType::Password)
            .with_username("user@example.com")
            .with_password("secret123");

        storage.add_entry(&entry).unwrap();

        // Drop to release database lock before reopening
        drop(storage);

        // Reopen and unlock
        let mut storage2 = VaultStorage::open(&vault_path).unwrap();
        storage2.unlock(&master_key).unwrap();

        let entries = storage2.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
    }

    #[test]
    fn test_search_entries() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test_vault");

        let master_key = MasterKey::generate();
        let kdf_params = crate::crypto::KeyDeriver::generate_params();

        let mut storage = VaultStorage::create(
            &vault_path,
            "Test",
            &master_key,
            kdf_params,
            "fp".to_string(),
        )
        .unwrap();

        // Add entries
        storage
            .add_entry(
                &VaultEntry::new("GitHub", crate::models::EntryType::Password)
                    .with_tags(vec!["work".to_string()]),
            )
            .unwrap();
        storage
            .add_entry(
                &VaultEntry::new("GitLab", crate::models::EntryType::Password)
                    .with_tags(vec!["personal".to_string()]),
            )
            .unwrap();
        storage
            .add_entry(
                &VaultEntry::new("AWS", crate::models::EntryType::Password)
                    .with_tags(vec!["work".to_string()]),
            )
            .unwrap();

        // Search by query
        let filter = SearchFilter::new().with_query("git");
        let results = storage.search_entries(&filter).unwrap();
        assert_eq!(results.len(), 2);

        // Search by tag
        let filter = SearchFilter::new().with_tags(vec!["work".to_string()]);
        let results = storage.search_entries(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    // Small, fast KDF parameters for exercising the unlock paths without
    // paying for realistic Argon2 cost on every test.
    fn cheap_params(salt: &[u8]) -> KdfParams {
        KdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
            salt: salt.to_vec(),
        }
    }

    #[test]
    fn test_unlock_with_password_honest_vault() {
        // A vault created honoring its recorded parameters (as the CLI now
        // does) unlocks via the honest path with no legacy fallback, and its
        // key equals a fresh derivation over the stored parameters — which is
        // exactly what the GUI/agent do. This is the CLI↔GUI interop guarantee.
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault");

        let password = b"interop-password";
        let params = cheap_params(b"interop-salt-1234");
        let master_key = KeyDeriver::derive_from_password(password, &params).unwrap();

        let storage = VaultStorage::create(
            &vault_path,
            "V",
            &master_key,
            params.clone(),
            "fp".to_string(),
        )
        .unwrap();
        drop(storage);

        let mut storage = VaultStorage::open(&vault_path).unwrap();
        let (key, was_legacy) = storage.unlock_with_password_ext(password).unwrap();
        assert!(
            !was_legacy,
            "honest vault must not need the legacy fallback"
        );

        let loaded = KdfParamsStorage::load(&vault_path).unwrap();
        let gui_key = KeyDeriver::derive_from_password(password, &loaded).unwrap();
        assert_eq!(
            key.as_bytes(),
            gui_key.as_bytes(),
            "CLI key must match the GUI/agent derivation over the stored params"
        );
    }

    #[test]
    fn test_unlock_with_password_legacy_fallback_and_heal() {
        // Simulate a pre-2.3 CLI vault: the metadata is encrypted under the key
        // Argon2::default() produces, but kdf_params.json *lies* about the cost
        // parameters (they were recorded but never actually applied).
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault");

        let password = b"legacy-password";
        let salt = b"legacy-salt-16by".to_vec();

        let legacy_key = KeyDeriver::derive_legacy_default(password, &salt).unwrap();
        let lying_params = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost: 8192, // recorded but never applied (real key is at Argon2 default)
            time_cost: 3,
            parallelism: 4,
            salt: salt.clone(),
        };
        let storage = VaultStorage::create(
            &vault_path,
            "Legacy",
            &legacy_key,
            lying_params,
            "fp".to_string(),
        )
        .unwrap();
        drop(storage);

        // Honest derivation over the lying params fails; the fallback wins.
        let mut storage = VaultStorage::open(&vault_path).unwrap();
        let (key, was_legacy) = storage.unlock_with_password_ext(password).unwrap();
        assert!(was_legacy, "legacy vault must be opened via the fallback");
        assert_eq!(key.as_bytes(), legacy_key.as_bytes());

        // Self-heal, then confirm the honest path alone now works and yields
        // the same key (metadata-only correction, no re-encryption).
        storage.heal_legacy_kdf_params().unwrap();
        drop(storage);

        let mut storage = VaultStorage::open(&vault_path).unwrap();
        let (key2, was_legacy2) = storage.unlock_with_password_ext(password).unwrap();
        assert!(!was_legacy2, "after healing, no fallback should be needed");
        assert_eq!(key2.as_bytes(), legacy_key.as_bytes());
    }

    #[test]
    fn test_unlock_with_password_wrong_password_fails() {
        // A genuinely wrong password fails both the honest and legacy paths.
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault");

        let params = cheap_params(b"wrongpw-salt-16b");
        let master_key = KeyDeriver::derive_from_password(b"right-password", &params).unwrap();
        let storage =
            VaultStorage::create(&vault_path, "V", &master_key, params, "fp".to_string()).unwrap();
        drop(storage);

        let mut storage = VaultStorage::open(&vault_path).unwrap();
        assert!(storage.unlock_with_password_ext(b"wrong-password").is_err());
    }
}
