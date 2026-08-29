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
    tracing::warn!(
        "memory locking unsupported on this platform; master key pages may be swappable"
    );
    false
}

#[cfg(not(unix))]
fn unlock_region(_ptr: *const u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_holds_key_and_master_key_round_trips() {
        // Construction takes ownership of the raw bytes; materializing a
        // MasterKey must return them unchanged.
        let raw = [0x5au8; 32];
        let held = LockedMasterKey::new(raw);
        assert_eq!(held.master_key().as_bytes(), &raw);
    }

    #[test]
    fn master_key_returns_independent_equal_copies() {
        // Each `master_key()` call yields a fresh, zeroize-on-drop copy.
        // Dropping one copy must not disturb the held key or another copy.
        let raw = [0x11u8; 32];
        let held = LockedMasterKey::new(raw);

        let a = held.master_key();
        let b = held.master_key();
        assert_eq!(a.as_bytes(), &raw);
        assert_eq!(b.as_bytes(), &raw);

        drop(a);
        assert_eq!(held.master_key().as_bytes(), &raw);
        assert_eq!(b.as_bytes(), &raw);
    }

    #[test]
    fn distinct_keys_do_not_alias() {
        let k1 = LockedMasterKey::new([0x01u8; 32]);
        let k2 = LockedMasterKey::new([0x02u8; 32]);
        assert_eq!(k1.master_key().as_bytes(), &[0x01u8; 32]);
        assert_eq!(k2.master_key().as_bytes(), &[0x02u8; 32]);
    }

    #[test]
    fn is_locked_reports_status_without_affecting_key() {
        // On a typical unix host with a sane RLIMIT_MEMLOCK this is `true`,
        // but graceful degradation means `false` is equally valid (hardened
        // sandboxes, containers, non-unix). Either way the key still works.
        let held = LockedMasterKey::new([0x7fu8; 32]);
        let _locked: bool = held.is_locked();
        assert_eq!(held.master_key().as_bytes(), &[0x7fu8; 32]);
    }

    #[test]
    fn explicit_drop_runs_clean() {
        // Drop zeroizes then (if locked) munlocks. It must never panic,
        // regardless of whether mlock succeeded. Post-free zeroization can't
        // be observed safely, so the observable contract is simply that drop
        // completes without panicking.
        let held = LockedMasterKey::new([0x33u8; 32]);
        drop(held);
    }

    #[test]
    fn repeated_construct_and_drop_cycles_are_stable() {
        // Many lock/zeroize/unlock cycles must neither panic nor corrupt
        // subsequent keys.
        for i in 0u16..256 {
            let byte = i as u8;
            let held = LockedMasterKey::new([byte; 32]);
            assert_eq!(held.master_key().as_bytes(), &[byte; 32]);
            // dropped at end of each iteration
        }
    }

    // ---- graceful-degradation path: an mlock failure must not panic ----

    #[cfg(unix)]
    #[test]
    fn lock_region_round_trips_on_a_real_allocation() {
        // A small, live, page-backed allocation should lock on a normal host.
        // If the host forbids it (RLIMIT_MEMLOCK == 0) we tolerate `false`,
        // but the call must never panic.
        let buf = Box::new([0u8; 32]);
        if lock_region(buf.as_ptr(), buf.len()) {
            unlock_region(buf.as_ptr(), buf.len());
        }
    }

    #[cfg(unix)]
    #[test]
    fn lock_region_returns_false_on_an_unlockable_range() {
        // Deterministically exercise the failure branch: an absurd length
        // cannot be fully backed by mapped memory, so mlock(2) returns -1.
        // `lock_region` is a safe fn and mlock only *validates* the range
        // (it never dereferences it), so this is sound; it must log and
        // return `false` rather than panic — the same path taken when
        // RLIMIT_MEMLOCK is exhausted.
        let buf = Box::new([0u8; 32]);
        let bogus_len = usize::MAX / 2;
        assert!(!lock_region(buf.as_ptr(), bogus_len));
    }

    #[cfg(unix)]
    #[test]
    fn unlock_region_on_unlocked_memory_does_not_panic() {
        // munlock on a valid but never-locked region is ignored by the
        // wrapper; it must simply not panic.
        let buf = Box::new([0u8; 32]);
        unlock_region(buf.as_ptr(), buf.len());
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_fallback_is_coherent() {
        // On platforms without mlock the fallback reports "not locked" and
        // unlock is a no-op, yet the public key still round-trips.
        let buf = Box::new([0u8; 32]);
        assert!(!lock_region(buf.as_ptr(), buf.len()));
        unlock_region(buf.as_ptr(), buf.len());

        let held = LockedMasterKey::new([0x99u8; 32]);
        assert!(!held.is_locked());
        assert_eq!(held.master_key().as_bytes(), &[0x99u8; 32]);
    }
}
