//! Client-side key derivation helper.
//!
//! Anything connecting to `vaultic-agent` to unlock a vault needs to:
//! 1. Read the vault's `kdf_params.json`.
//! 2. Run Argon2id over the user's password with those params.
//! 3. Hex-encode the resulting 32-byte master key for the wire.
//!
//! That's the same three steps for every client (GUI today, future
//! browser-extension host, future CLI-via-agent), so the canonical
//! implementation lives here. The agent itself never runs this — see
//! the threat-model section of `docs/AGENT_PROTOCOL.md` for why the
//! password stays on the client side.

use std::path::Path;

use thiserror::Error;
use zeroize::Zeroize;

use crate::crypto::KeyDeriver;
use crate::storage::KdfParamsStorage;

/// Errors raised by the unlock-key derivation helper.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("kdf_params.json not found in {0}")]
    KdfParamsMissing(String),

    #[error("could not read kdf_params.json: {0}")]
    KdfParamsIo(String),

    #[error("kdf failed: {0}")]
    Kdf(String),
}

/// 32 bytes of derived key as hex (64 chars). Wrapped so callers don't
/// confuse it with arbitrary user input. Zeroizes on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKeyHex(String);

impl DerivedKeyHex {
    /// Borrow the hex string for the `Method::Unlock` wire payload. Caller
    /// is expected to discard the resulting String soon after sending.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Take ownership for sending over the wire. The instance is consumed
    /// and zeroized.
    pub fn into_hex(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

/// Derive the master-key bytes for `vault_path` using `password`. Returns
/// hex-encoded 32 bytes ready to put on the wire as
/// `Method::Unlock { derived_key_hex }`.
pub fn derive_for_unlock(vault_path: &Path, password: &str) -> Result<DerivedKeyHex, KeyError> {
    if !KdfParamsStorage::exists(vault_path) {
        return Err(KeyError::KdfParamsMissing(vault_path.display().to_string()));
    }
    let params =
        KdfParamsStorage::load(vault_path).map_err(|e| KeyError::KdfParamsIo(e.to_string()))?;
    let key = KeyDeriver::derive_from_password(password.as_bytes(), &params)
        .map_err(|e| KeyError::Kdf(e.to_string()))?;
    let hex = hex_encode(key.as_bytes());
    Ok(DerivedKeyHex(hex))
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use tempfile::TempDir;

    #[test]
    fn derive_for_unlock_round_trip() {
        // Build a real vault on disk, then derive its key from the same
        // password, and check that the bytes round-trip with what we
        // would have written.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault");

        let key = MasterKey::from_bytes([0xab; 32]);
        let _storage = crate::storage::VaultStorage::create(
            &path,
            "test",
            &key,
            KeyDeriver::generate_params(),
            "owner".to_string(),
        )
        .unwrap();

        // Re-derive using the helper. The result depends on the ACTUAL
        // password, not the bytes we used to create with — so we only
        // verify the helper completes and returns 64 hex chars. Wrong-key
        // detection is the daemon's job (BadKey error).
        let derived = derive_for_unlock(&path, "hunter2").unwrap();
        assert_eq!(derived.as_hex().len(), 64);
        assert!(derived.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derive_for_unlock_missing_params_errors() {
        let dir = TempDir::new().unwrap();
        // We avoid `unwrap_err` because DerivedKeyHex deliberately has no
        // Debug impl (printing it would leak the key).
        match derive_for_unlock(dir.path(), "anything") {
            Err(KeyError::KdfParamsMissing(_)) => {}
            Err(other) => panic!("unexpected error: {:?}", other),
            Ok(_) => panic!("expected KdfParamsMissing"),
        }
    }

    #[test]
    fn derive_for_unlock_same_input_same_output() {
        // Determinism: same vault + same password → same hex.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault");
        let key = MasterKey::from_bytes([0x11; 32]);
        let _ = crate::storage::VaultStorage::create(
            &path,
            "test",
            &key,
            KeyDeriver::generate_params(),
            "owner".to_string(),
        )
        .unwrap();

        let a = derive_for_unlock(&path, "same-password").unwrap();
        let b = derive_for_unlock(&path, "same-password").unwrap();
        assert_eq!(a.as_hex(), b.as_hex());
    }
}
