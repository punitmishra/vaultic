//! Helpers that let the sync CLI talk to `vaultic-agent` when it's running.
//!
//! All operations here are **best-effort**: if the agent isn't running, the
//! socket is unreachable, or the call fails for any other reason, we return
//! the failure as a diagnostic but don't propagate it as a CLI error. The
//! agent is an optional accelerator, not a requirement.
//!
//! See [`docs/AGENT_PROTOCOL.md`](../../docs/AGENT_PROTOCOL.md) for the wire
//! format and threat model.

use std::path::{Path, PathBuf};

use crate::agent::client::AgentClient;
use crate::agent::paths;
use crate::agent::protocol::StatusView;
use crate::crypto::MasterKey;

/// Snapshot of the agent's state at one moment, suitable for `vaultic status`
/// and for the unlock/lock flow's "should we route through the agent?"
/// decision.
#[derive(Debug, Clone)]
pub struct AgentSnapshot {
    /// Resolved socket path. Always present even when the agent isn't
    /// running — it's the path we *would* talk to.
    pub socket_path: PathBuf,
    /// `Some(_)` if we connected and got a Status response; `None` if the
    /// agent isn't running or the call failed.
    pub status: Option<StatusView>,
}

impl AgentSnapshot {
    pub fn is_running(&self) -> bool {
        self.status.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.status.as_ref().map(|s| s.unlocked).unwrap_or(false)
    }

    /// True if the agent is unlocked AND for the same vault path the user
    /// is currently working with. Compared by canonical path strings —
    /// callers should pass an already-canonicalized path.
    pub fn is_unlocked_for(&self, vault_path: &Path) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        let agent_path = match self.status.as_ref().and_then(|s| s.vault_path.as_ref()) {
            Some(p) => p,
            None => return false,
        };
        Path::new(agent_path) == vault_path
    }
}

/// Probe the agent's current state. Never fails — returns a snapshot whose
/// `status` is `None` when the agent isn't reachable.
pub fn probe() -> AgentSnapshot {
    let socket_path = match paths::agent_socket_path() {
        Ok(p) => p,
        Err(_) => {
            return AgentSnapshot {
                socket_path: PathBuf::new(),
                status: None,
            }
        }
    };
    let socket_for_call = socket_path.clone();
    let status = run_async(async move {
        let mut client = AgentClient::connect(&socket_for_call).await.ok()?;
        client.status().await.ok()
    })
    .flatten();
    AgentSnapshot {
        socket_path,
        status,
    }
}

/// Tell a running agent to unlock for `vault_path` using the supplied master
/// key. Returns `Ok(true)` when the agent accepted the unlock, `Ok(false)`
/// when no agent is running (we did nothing), `Err(_)` when an agent is
/// running but the call failed (caller may want to surface this).
pub fn notify_agent_unlock(vault_path: &Path, key: &MasterKey) -> Result<bool, String> {
    let socket = match paths::agent_socket_path() {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let key_hex = hex_encode(key.as_bytes());
    let vault_path_str = vault_path.display().to_string();

    run_async(async move {
        let mut client = match AgentClient::connect(&socket).await {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };
        match client.unlock(vault_path_str, key_hex).await {
            Ok(()) => Ok(true),
            Err(e) => Err(format!("agent unlock failed: {}", e)),
        }
    })
    .unwrap_or(Ok(false))
}

/// Tell a running agent to lock. Best-effort: returns `Ok(true)` if we sent
/// the lock, `Ok(false)` if no agent is running. Errors only on a running
/// agent that rejected the call.
pub fn notify_agent_lock() -> Result<bool, String> {
    let socket = match paths::agent_socket_path() {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    run_async(async move {
        let mut client = match AgentClient::connect(&socket).await {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };
        match client.lock().await {
            Ok(()) => Ok(true),
            Err(e) => Err(format!("agent lock failed: {}", e)),
        }
    })
    .unwrap_or(Ok(false))
}

/// Run a future to completion on a single-thread runtime. Used by the sync
/// CLI to call into our async `AgentClient`. Same pattern the AI helpers
/// use elsewhere in this module. Returns `None` if the runtime itself
/// can't be built.
fn run_async<F, T>(fut: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    Some(rt.block_on(fut))
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

    #[test]
    fn snapshot_when_status_none_is_not_running() {
        let snap = AgentSnapshot {
            socket_path: PathBuf::from("/nope"),
            status: None,
        };
        assert!(!snap.is_running());
        assert!(!snap.is_unlocked());
        assert!(!snap.is_unlocked_for(Path::new("/some/vault")));
    }

    #[test]
    fn snapshot_when_locked_reports_running_but_locked() {
        let snap = AgentSnapshot {
            socket_path: PathBuf::from("/run/foo"),
            status: Some(StatusView {
                unlocked: false,
                vault_path: None,
                entry_count: None,
                expires_at: None,
            }),
        };
        assert!(snap.is_running());
        assert!(!snap.is_unlocked());
    }

    #[test]
    fn snapshot_unlocked_for_matches_only_same_path() {
        let snap = AgentSnapshot {
            socket_path: PathBuf::from("/run/foo"),
            status: Some(StatusView {
                unlocked: true,
                vault_path: Some("/home/alice/.vaultic".into()),
                entry_count: Some(42),
                expires_at: None,
            }),
        };
        assert!(snap.is_unlocked_for(Path::new("/home/alice/.vaultic")));
        assert!(!snap.is_unlocked_for(Path::new("/home/alice/.other")));
    }

    #[test]
    fn snapshot_unlocked_without_path_does_not_match() {
        // Defensive: shouldn't happen in practice (the daemon always sends a
        // vault_path when unlocked), but if it did, we'd refuse to route.
        let snap = AgentSnapshot {
            socket_path: PathBuf::from("/run/foo"),
            status: Some(StatusView {
                unlocked: true,
                vault_path: None,
                entry_count: None,
                expires_at: None,
            }),
        };
        assert!(!snap.is_unlocked_for(Path::new("/anything")));
    }
}
