//! Agent state machine: locked / unlocked, master key holder, inactivity timer.
//!
//! All access goes through methods that perform the authorization check
//! ("is the vault unlocked?") in one place, so socket dispatch code in
//! `server.rs` can stay flat.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use zeroize::Zeroize;

use crate::agent::locked_key::LockedMasterKey;
use crate::agent::protocol::{EntrySummary, StatusView, TotpView};
use crate::models::{SearchFilter, VaultEntry};
use crate::storage::VaultStorage;

/// How long the daemon stays unlocked without activity. Mirrors the existing
/// CLI session timeout.
pub const DEFAULT_INACTIVITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Errors raised by `AgentState` methods. These map onto the protocol's
/// stable `ErrorCode` taxonomy in `server.rs`.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("vault is locked")]
    Locked,

    #[error("entry {0} not found")]
    NotFound(Uuid),

    #[error("entry {0} has no totp_secret")]
    NoTotpSecret(Uuid),

    #[error("derived key did not unwrap vault metadata")]
    BadKey,

    #[error("vault io: {0}")]
    VaultIo(String),

    #[error("invalid hex in derived_key_hex: {0}")]
    InvalidHex(String),

    #[error("derived_key_hex must decode to exactly 32 bytes (got {0})")]
    BadKeyLength(usize),
}

pub type StateResult<T> = Result<T, StateError>;

/// Shared, mutable agent state. Wrap in `Arc` and share across tasks.
pub struct AgentState {
    inner: Mutex<Inner>,
    inactivity_timeout: std::time::Duration,
}

#[derive(Default)]
struct Inner {
    /// `None` when locked; `Some` when an `unlock` succeeded and we're
    /// holding the master key in memory (but NOT the sled handle).
    open: Option<OpenVault>,
    /// Wallclock instant the daemon will auto-lock at if no further activity
    /// resets it. `None` means no scheduled lock (vault is locked).
    expires_at: Option<DateTime<Utc>>,
}

/// What the agent caches when "unlocked": the path it can re-open at, and
/// the master key it can re-unlock with. **Crucially, NO open `VaultStorage`
/// handle.** sled enforces an exclusive process-wide lock on its database
/// directory, so holding a long-lived handle would prevent the CLI/TUI/GUI
/// from opening the same vault. Each method that needs storage opens and
/// drops it within its own scope.
struct OpenVault {
    vault_path: PathBuf,
    /// Held key, pinned into RAM with `mlock` so it can't be swapped to disk
    /// (issue #24). Zeroized + munlocked on drop.
    master_key: LockedMasterKey,
}

impl OpenVault {
    /// Open + unlock storage for one operation. The returned handle should
    /// be dropped before the next request hits this vault, otherwise the
    /// other vault clients will see "could not acquire lock" errors.
    fn open_storage(&self) -> StateResult<VaultStorage> {
        let mut storage =
            VaultStorage::open(&self.vault_path).map_err(|e| StateError::VaultIo(e.to_string()))?;
        let master_key = self.master_key.master_key();
        storage.unlock(&master_key).map_err(classify_unlock_error)?;
        Ok(storage)
    }
}

impl AgentState {
    pub fn new() -> Arc<Self> {
        Self::with_timeout(DEFAULT_INACTIVITY_TIMEOUT)
    }

    pub fn with_timeout(timeout: std::time::Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            inactivity_timeout: timeout,
        })
    }

    /// Public read of the daemon's current state. Doesn't reset the
    /// inactivity timer. Best-effort entry count: if opening sled fails
    /// (the CLI / TUI is using it concurrently), we report `None`.
    pub async fn status(&self) -> StatusView {
        let inner = self.inner.lock().await;
        let entry_count = inner.open.as_ref().and_then(|o| {
            o.open_storage()
                .and_then(|s| {
                    s.list_entries()
                        .map_err(|e| StateError::VaultIo(e.to_string()))
                })
                .ok()
                .map(|v| v.len())
        });
        StatusView {
            unlocked: inner.open.is_some(),
            vault_path: inner
                .open
                .as_ref()
                .map(|o| o.vault_path.display().to_string()),
            entry_count,
            expires_at: inner.expires_at,
        }
    }

    /// Cache the master key for `vault_path`. Verifies by briefly opening
    /// the vault and decrypting metadata, then drops the storage handle —
    /// the agent doesn't keep sled open between calls so the CLI / TUI /
    /// other tools can share the same database.
    pub async fn unlock(&self, vault_path: PathBuf, derived_key_hex: &str) -> StateResult<()> {
        let mut key_bytes = decode_key_hex(derived_key_hex)?;
        // Pin the held copy into RAM immediately; the transient stack copy in
        // `key_bytes` is zeroized below once it's no longer needed.
        let master_key = LockedMasterKey::new(key_bytes);
        key_bytes.zeroize();

        // Verify by opening + unlocking. The handle is dropped at the end
        // of this scope; we don't keep it.
        {
            let verify_key = master_key.master_key();
            let mut storage =
                VaultStorage::open(&vault_path).map_err(|e| StateError::VaultIo(e.to_string()))?;
            storage.unlock(&verify_key).map_err(classify_unlock_error)?;
        }

        let mut inner = self.inner.lock().await;
        inner.open = Some(OpenVault {
            vault_path,
            master_key,
        });
        inner.expires_at = Some(self.compute_expiry());
        Ok(())
    }

    /// Drop any held key. Idempotent.
    pub async fn lock(&self) {
        let mut inner = self.inner.lock().await;
        inner.open = None;
        inner.expires_at = None;
    }

    /// Sorted summaries (no secret fields) of every entry. Resets timer.
    pub async fn list_summary(&self) -> StateResult<Vec<EntrySummary>> {
        let mut inner = self.inner.lock().await;
        let open = inner.open.as_ref().ok_or(StateError::Locked)?;
        let storage = open.open_storage()?;
        let entries = storage
            .list_entries()
            .map_err(|e| StateError::VaultIo(e.to_string()))?;
        let summaries = entries.iter().map(entry_to_summary).collect();
        inner.expires_at = Some(self.compute_expiry());
        Ok(summaries)
    }

    /// Full entry by id, including secret fields. Resets timer.
    pub async fn get_entry(&self, id: Uuid) -> StateResult<VaultEntry> {
        let mut inner = self.inner.lock().await;
        let open = inner.open.as_ref().ok_or(StateError::Locked)?;
        let storage = open.open_storage()?;
        let entry = storage
            .get_entry(&id)
            .map_err(|e| StateError::VaultIo(e.to_string()))?
            .ok_or(StateError::NotFound(id))?;
        inner.expires_at = Some(self.compute_expiry());
        Ok(entry)
    }

    /// Current TOTP code for an entry that has a totp_secret. Resets timer.
    pub async fn get_totp(&self, id: Uuid) -> StateResult<TotpView> {
        let mut inner = self.inner.lock().await;
        let open = inner.open.as_ref().ok_or(StateError::Locked)?;
        let storage = open.open_storage()?;
        let entry = storage
            .get_entry(&id)
            .map_err(|e| StateError::VaultIo(e.to_string()))?
            .ok_or(StateError::NotFound(id))?;
        let secret = entry.totp_secret.ok_or(StateError::NoTotpSecret(id))?;
        let totp = crate::totp::Totp::new(secret.expose())
            .map_err(|e| StateError::VaultIo(format!("totp: {}", e)))?;
        let display = crate::totp::TotpDisplay::from_totp(&totp)
            .map_err(|e| StateError::VaultIo(format!("totp: {}", e)))?;
        inner.expires_at = Some(self.compute_expiry());
        Ok(TotpView {
            code: display.code,
            period_remaining_seconds: display.remaining as u32,
            period_total_seconds: display.period as u32,
        })
    }

    /// Fuzzy-search summaries. Resets timer.
    pub async fn search(&self, query: &str) -> StateResult<Vec<EntrySummary>> {
        let filter = SearchFilter::new().with_query(query);
        self.list_filtered(filter).await
    }

    /// Full-filter list. Same set of summaries that
    /// `storage::search_entries(&filter)` would produce locally. Resets
    /// the inactivity timer.
    pub async fn list_filtered(&self, filter: SearchFilter) -> StateResult<Vec<EntrySummary>> {
        let mut inner = self.inner.lock().await;
        let open = inner.open.as_ref().ok_or(StateError::Locked)?;
        let storage = open.open_storage()?;
        let entries = storage
            .search_entries(&filter)
            .map_err(|e| StateError::VaultIo(e.to_string()))?;
        let summaries = entries.iter().map(entry_to_summary).collect();
        inner.expires_at = Some(self.compute_expiry());
        Ok(summaries)
    }

    /// Returns `true` if the inactivity timer has elapsed and the daemon
    /// should auto-lock. Caller is responsible for calling `lock()` if so
    /// (and emitting the `SessionExpired` event).
    pub async fn is_expired(&self) -> bool {
        let inner = self.inner.lock().await;
        match inner.expires_at {
            Some(at) => Utc::now() >= at,
            None => false,
        }
    }

    fn compute_expiry(&self) -> DateTime<Utc> {
        let timeout = chrono::Duration::from_std(self.inactivity_timeout)
            // 15 minutes always fits; this only fails on absurdly large values.
            .unwrap_or_else(|_| chrono::Duration::seconds(900));
        Utc::now() + timeout
    }
}

fn entry_to_summary(entry: &VaultEntry) -> EntrySummary {
    EntrySummary {
        id: entry.id,
        name: entry.name.clone(),
        username: entry.username.clone(),
        url: entry.url.clone(),
        tags: entry.tags.clone(),
        folder: entry.folder.clone(),
        favorite: entry.favorite,
        has_password: entry.password.is_some(),
        has_totp: entry.totp_secret.is_some(),
        entry_type: entry.entry_type.clone(),
        password_strength: entry.password_strength,
        last_accessed: entry.last_accessed,
    }
}

fn decode_key_hex(s: &str) -> StateResult<[u8; 32]> {
    if s.len() != 64 {
        return Err(StateError::BadKeyLength(s.len() / 2));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| StateError::InvalidHex(e.to_string()))?;
        out[i] = byte;
    }
    Ok(out)
}

/// Map `VaultStorage::unlock` errors to either `BadKey` (the typical case —
/// wrong password) or a generic VaultIo for anything else (corrupt vault,
/// missing metadata, etc.).
fn classify_unlock_error(e: crate::storage::StorageError) -> StateError {
    use crate::storage::StorageError;
    match e {
        // Decryption failure during metadata load is the BadKey signal.
        StorageError::Crypto(_) => StateError::BadKey,
        StorageError::InvalidData => StateError::BadKey,
        other => StateError::VaultIo(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_hex_accepts_32_bytes() {
        let s = "ab".repeat(32);
        let bytes = decode_key_hex(&s).unwrap();
        assert_eq!(bytes, [0xabu8; 32]);
    }

    #[test]
    fn decode_key_hex_rejects_short() {
        let s = "ab".repeat(31);
        assert!(matches!(
            decode_key_hex(&s),
            Err(StateError::BadKeyLength(_))
        ));
    }

    #[test]
    fn decode_key_hex_rejects_non_hex() {
        let mut s = "ab".repeat(32);
        s.replace_range(0..2, "zz");
        assert!(matches!(decode_key_hex(&s), Err(StateError::InvalidHex(_))));
    }

    #[tokio::test]
    async fn status_locked_by_default() {
        let state = AgentState::new();
        let s = state.status().await;
        assert!(!s.unlocked);
        assert!(s.vault_path.is_none());
        assert!(s.expires_at.is_none());
    }

    #[tokio::test]
    async fn list_when_locked_returns_locked_error() {
        let state = AgentState::new();
        let err = state.list_summary().await.unwrap_err();
        assert!(matches!(err, StateError::Locked));
    }

    #[tokio::test]
    async fn get_when_locked_returns_locked_error() {
        let state = AgentState::new();
        let err = state.get_entry(Uuid::nil()).await.unwrap_err();
        assert!(matches!(err, StateError::Locked));
    }
}
