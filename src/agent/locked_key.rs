//! Memory-locked holder for the daemon's unlocked master key (issue #24).
//!
//! While `vaultic-agent` is unlocked it keeps the 32-byte master key resident
//! in memory. Ordinary heap pages can be paged out to swap by the kernel,
//! which would write plaintext key material to disk. `mlock(2)` pins the
//! pages backing the key so they are never swapped.
//!
//! The bytes live in a `Box` so the address is stable for the lifetime of the
//! value — `mlock` operates on a fixed address range, so a stack-resident or
//! movable buffer would be unsafe to lock. On drop the buffer is zeroized
//! while still locked, then unlocked, then freed.
//!
//! Locking is best-effort: on platforms without `mlock`, or when the process
//! lacks the privilege / hits `RLIMIT_MEMLOCK`, we log a warning and continue
//! with an unlocked (but still zeroize-on-drop) buffer rather than refusing to
//! unlock the vault.

use zeroize::Zeroize;

use crate::crypto::MasterKey;

/// The daemon's held master key, pinned into RAM with `mlock` when possible.
///
/// This type intentionally exposes only the ability to materialize a
/// short-lived [`MasterKey`] for a single storage operation; it never derefs
/// to the raw bytes for callers.
pub struct LockedMasterKey {
    /// Heap-boxed so the pointer handed to `mlock` stays valid for the whole
    /// lifetime of this value.
    bytes: Box<[u8; 32]>,
    /// Whether `mlock` succeeded — determines if we `munlock` on drop.
    locked: bool,
}

impl LockedMasterKey {
    /// Take ownership of the raw key bytes and pin them in memory.
    ///
    /// If locking fails the key is still held (and zeroized on drop); only the
    /// swap-protection guarantee is lost, and a warning is logged.
    pub fn new(key: [u8; 32]) -> Self {
        let bytes = Box::new(key);
        let locked = lock_region(bytes.as_ptr(), bytes.len());
        Self { bytes, locked }
    }

    /// Materialize a `MasterKey` for one storage operation. The returned value
    /// is a copy that zeroizes on drop; keep its scope as small as possible.
    pub fn master_key(&self) -> MasterKey {
        MasterKey::from_bytes(*self.bytes)
    }

    /// Whether the key's pages are currently pinned into RAM. Primarily for
    /// diagnostics and tests.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedMasterKey {
    fn drop(&mut self) {
        // Wipe while the pages are still locked, then unlock.
        self.bytes.zeroize();
        if self.locked {
            unlock_region(self.bytes.as_ptr(), self.bytes.len());
        }
    }
}

#[cfg(unix)]
fn lock_region(ptr: *const u8, len: usize) -> bool {
    // SAFETY: `ptr`/`len` describe a live, owned heap allocation held by the
    // caller for at least as long as the lock (until the matching munlock in
    // Drop).
    let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if rc == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            error = %err,
            "mlock failed; master key pages may be swappable (check RLIMIT_MEMLOCK)"
        );
        false
    }
}

#[cfg(unix)]
fn unlock_region(ptr: *const u8, len: usize) {
    // SAFETY: same region previously locked by `lock_region`.
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
fn lock_region(_ptr: *const u8, _len: usize) -> bool {
    tracing::warn!("memory locking unsupported on this platform; master key pages may be swappable");
    false
}

#[cfg(not(unix))]
fn unlock_region(_ptr: *const u8, _len: usize) {}
