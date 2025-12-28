//! Session management for Vaultic
//!
//! Handles unlock state persistence between CLI invocations.
//! Uses file-based storage with compression and encryption.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{Cipher, MasterKey};

/// Session errors
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session expired")]
    Expired,

    #[error("Session not found")]
    NotFound,

    #[error("Session corrupted")]
    Corrupted,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

pub type SessionResult<T> = Result<T, SessionError>;

/// Session data stored on disk (compressed + encrypted)
#[derive(Serialize, Deserialize)]
struct SessionData {
    /// Path to the vault
    vault_path: PathBuf,
    /// The master key (will be encrypted)
    master_key: [u8; 32],
    /// When session expires
    expires_at: DateTime<Utc>,
    /// When session was created
    created_at: DateTime<Utc>,
}

/// Lightweight session manager
pub struct SessionManager {
    session_path: PathBuf,
    machine_key: [u8; 32],
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> SessionResult<Self> {
        let vaultic_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".vaultic");

        // Ensure directory exists
        fs::create_dir_all(&vaultic_dir)?;

        let session_path = vaultic_dir.join(".session");
        let machine_key = derive_machine_key();

        Ok(Self {
            session_path,
            machine_key,
        })
    }

    /// Create a new session after successful unlock
    pub fn create(
        &self,
        vault_path: &Path,
        master_key: &MasterKey,
        timeout_minutes: u32,
    ) -> SessionResult<()> {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(timeout_minutes as i64);

        let session = SessionData {
            vault_path: vault_path.to_path_buf(),
            master_key: *master_key.as_bytes(),
            expires_at,
            created_at: now,
        };

        // Serialize
        let json = serde_json::to_vec(&session)
            .map_err(|e| SessionError::Serialization(e.to_string()))?;

        // Compress
        let compressed = compress(&json)?;

        // Encrypt
        let cipher = Cipher::new(&self.machine_key);
        let encrypted = cipher.encrypt(&compressed)?;

        // Write with restrictive permissions
        write_secure(&self.session_path, &encrypted)?;

        Ok(())
    }

    /// Load existing session, returns (vault_path, master_key) if valid
    pub fn load(&self) -> SessionResult<(PathBuf, MasterKey)> {
        // Read file
        let encrypted = fs::read(&self.session_path).map_err(|_| SessionError::NotFound)?;

        // Decrypt
        let cipher = Cipher::new(&self.machine_key);
        let compressed = cipher.decrypt(&encrypted).map_err(|_| SessionError::Corrupted)?;

        // Decompress
        let json = decompress(&compressed)?;

        // Deserialize
        let session: SessionData = serde_json::from_slice(&json)
            .map_err(|_| SessionError::Corrupted)?;

        // Check expiration
        if Utc::now() > session.expires_at {
            // Clean up expired session
            let _ = fs::remove_file(&self.session_path);
            return Err(SessionError::Expired);
        }

        Ok((
            session.vault_path,
            MasterKey::from_bytes(session.master_key),
        ))
    }

    /// Extend session timeout
    pub fn refresh(&self, additional_minutes: u32) -> SessionResult<()> {
        let (vault_path, master_key) = self.load()?;
        self.create(&vault_path, &master_key, additional_minutes)
    }

    /// Destroy session (lock)
    pub fn destroy(&self) -> SessionResult<()> {
        if self.session_path.exists() {
            // Overwrite with zeros before deleting
            let size = fs::metadata(&self.session_path)?.len() as usize;
            let zeros = vec![0u8; size];
            fs::write(&self.session_path, &zeros)?;
            fs::remove_file(&self.session_path)?;
        }
        Ok(())
    }

    /// Check if a valid session exists (without loading the key)
    pub fn is_active(&self) -> bool {
        self.load().is_ok()
    }

    /// Get session info without exposing the key
    pub fn info(&self) -> Option<SessionInfo> {
        let encrypted = fs::read(&self.session_path).ok()?;
        let cipher = Cipher::new(&self.machine_key);
        let compressed = cipher.decrypt(&encrypted).ok()?;
        let json = decompress(&compressed).ok()?;
        let session: SessionData = serde_json::from_slice(&json).ok()?;

        if Utc::now() > session.expires_at {
            return None;
        }

        Some(SessionInfo {
            vault_path: session.vault_path,
            expires_at: session.expires_at,
            created_at: session.created_at,
        })
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        self.machine_key.zeroize();
    }
}

/// Session info (safe to expose)
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub vault_path: PathBuf,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl SessionInfo {
    /// Minutes remaining until expiration
    pub fn minutes_remaining(&self) -> i64 {
        (self.expires_at - Utc::now()).num_minutes().max(0)
    }
}

/// Derive a machine-specific key for session encryption
fn derive_machine_key() -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Collect machine-specific data
    let username = whoami::username();
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());

    // On macOS/Linux, try to get a stable machine identifier
    let machine_id = get_machine_id();

    // Combine into a stable key
    let mut hasher = Sha256::new();
    hasher.update(b"vaultic-session-v1:");
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(hostname.as_bytes());
    hasher.update(b":");
    hasher.update(machine_id.as_bytes());

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Get a stable machine identifier
fn get_machine_id() -> String {
    // Try /etc/machine-id (Linux)
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        return id.trim().to_string();
    }

    // Try /var/lib/dbus/machine-id (Linux fallback)
    if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
        return id.trim().to_string();
    }

    // macOS: Use IOPlatformUUID via ioreg (cached approach)
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return uuid.to_string();
                    }
                }
            }
        }
    }

    // Fallback: use home directory path (less ideal but stable)
    dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "fallback".to_string())
}

/// Compress data using DEFLATE
fn compress(data: &[u8]) -> SessionResult<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Decompress DEFLATE data
fn decompress(data: &[u8]) -> SessionResult<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Write file with secure permissions (owner read/write only)
fn write_secure(path: &Path, data: &[u8]) -> SessionResult<()> {
    fs::write(path, data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_manager() -> (SessionManager, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let mgr = SessionManager {
            session_path: dir.path().join(".session"),
            machine_key: [0x42; 32],
        };
        (mgr, dir)
    }

    #[test]
    fn test_session_lifecycle() {
        let (mgr, _dir) = test_manager();
        let vault_path = PathBuf::from("/test/vault");
        let master_key = MasterKey::from_bytes([0xAB; 32]);

        // Create session
        mgr.create(&vault_path, &master_key, 15).unwrap();

        // Load session
        let (loaded_path, loaded_key) = mgr.load().unwrap();
        assert_eq!(loaded_path, vault_path);
        assert_eq!(loaded_key.as_bytes(), master_key.as_bytes());

        // Check info
        let info = mgr.info().unwrap();
        assert!(info.minutes_remaining() > 0);

        // Destroy session
        mgr.destroy().unwrap();
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_compression() {
        let data = b"hello world hello world hello world";
        let compressed = compress(data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_expired_session() {
        let (mgr, _dir) = test_manager();
        let vault_path = PathBuf::from("/test/vault");
        let master_key = MasterKey::from_bytes([0xAB; 32]);

        // Create session with 0 minute timeout (already expired)
        let session = SessionData {
            vault_path: vault_path.clone(),
            master_key: *master_key.as_bytes(),
            expires_at: Utc::now() - Duration::minutes(1), // Already expired
            created_at: Utc::now() - Duration::minutes(2),
        };

        let json = serde_json::to_vec(&session).unwrap();
        let compressed = compress(&json).unwrap();
        let cipher = Cipher::new(&mgr.machine_key);
        let encrypted = cipher.encrypt(&compressed).unwrap();
        fs::write(&mgr.session_path, &encrypted).unwrap();

        // Should fail with Expired
        assert!(matches!(mgr.load(), Err(SessionError::Expired)));
    }
}
