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

use uuid::Uuid;

use crate::agent::client::{AgentClient, ClientError};
use crate::agent::paths;
use crate::agent::protocol::{EntrySummary, ErrorCode, StatusView, TotpView};
use crate::crypto::MasterKey;
use crate::models::{SearchFilter, VaultEntry};

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

/// Read-through fetch of a vault entry via a running agent.
///
/// Three-state return:
/// - `None` — the agent isn't routable (not running, locked, or unlocked for a
///   different vault). Caller should fall back to opening sled directly.
/// - `Some(Ok(entry))` — found and returned.
/// - `Some(Err(msg))` — the agent was routable when we probed, but the
///   subsequent operation failed (locked mid-call, no match, selection
///   cancelled, etc.). Surface the message; do not silently fall back, since
///   the caller usually has no CLI session to fall back to.
///
/// `pick` is invoked when there's more than one fuzzy-search match. It runs
/// synchronously on the same thread as this call (current-thread runtime), so
/// it's fine to drive an interactive prompt from inside it. Return `None` to
/// abort.
pub fn route_get_entry<F>(
    vault_path: &Path,
    query: &str,
    pick: F,
) -> Option<Result<VaultEntry, String>>
where
    F: FnOnce(&[EntrySummary]) -> Option<usize>,
{
    let socket = paths::agent_socket_path().ok()?;
    route_get_entry_at(&socket, vault_path, query, pick)
}

/// Same as [`route_get_entry`] but takes the socket path explicitly. Lets tests
/// point at a temp socket without going through `paths::agent_socket_path`.
pub(crate) fn route_get_entry_at<F>(
    socket: &Path,
    vault_path: &Path,
    query: &str,
    pick: F,
) -> Option<Result<VaultEntry, String>>
where
    F: FnOnce(&[EntrySummary]) -> Option<usize>,
{
    let socket = socket.to_path_buf();
    let query = query.to_string();
    let vault_path = vault_path.to_path_buf();
    run_async(async move {
        let mut client = AgentClient::connect(&socket).await.ok()?;
        if !is_unlocked_for_vault(&mut client, &vault_path).await {
            return None;
        }
        // Routable from here on; subsequent failures are user-visible.
        let summaries = match client.search(query.clone()).await {
            Ok(s) => s,
            Err(e) => return Some(Err(format!("agent search failed: {}", explain(&e)))),
        };
        if summaries.is_empty() {
            return Some(Err(format!("No entry found matching '{}'", query)));
        }
        // Cap at 10 like the local search path.
        let summaries: Vec<EntrySummary> = summaries.into_iter().take(10).collect();
        let idx = if summaries.len() == 1 {
            0
        } else {
            match pick(&summaries) {
                Some(i) => i,
                None => return Some(Err("selection cancelled".to_string())),
            }
        };
        let id = summaries[idx].id;
        match client.get_entry(id).await {
            Ok(e) => Some(Ok(e)),
            Err(e) => Some(Err(format!("agent get_entry failed: {}", explain(&e)))),
        }
    })
    .flatten()
}

/// Read-through TOTP fetch via a running agent. Same three-state return
/// semantics as [`route_get_entry`]. The returned `(Uuid, TotpView)` lets the
/// caller reuse the entry id for subsequent ticks of a watch loop without
/// re-running the search every second.
pub fn route_get_totp<F>(
    vault_path: &Path,
    query: &str,
    pick: F,
) -> Option<Result<(Uuid, String, TotpView), String>>
where
    F: FnOnce(&[EntrySummary]) -> Option<usize>,
{
    let socket = paths::agent_socket_path().ok()?;
    route_get_totp_at(&socket, vault_path, query, pick)
}

pub(crate) fn route_get_totp_at<F>(
    socket: &Path,
    vault_path: &Path,
    query: &str,
    pick: F,
) -> Option<Result<(Uuid, String, TotpView), String>>
where
    F: FnOnce(&[EntrySummary]) -> Option<usize>,
{
    let socket = socket.to_path_buf();
    let query = query.to_string();
    let vault_path = vault_path.to_path_buf();
    run_async(async move {
        let mut client = AgentClient::connect(&socket).await.ok()?;
        if !is_unlocked_for_vault(&mut client, &vault_path).await {
            return None;
        }
        let summaries = match client.search(query.clone()).await {
            Ok(s) => s,
            Err(e) => return Some(Err(format!("agent search failed: {}", explain(&e)))),
        };
        if summaries.is_empty() {
            return Some(Err(format!("No entry found matching '{}'", query)));
        }
        let summaries: Vec<EntrySummary> = summaries.into_iter().take(10).collect();
        let idx = if summaries.len() == 1 {
            0
        } else {
            match pick(&summaries) {
                Some(i) => i,
                None => return Some(Err("selection cancelled".to_string())),
            }
        };
        let id = summaries[idx].id;
        let name = summaries[idx].name.clone();
        match client.get_totp(id).await {
            Ok(view) => Some(Ok((id, name, view))),
            Err(e) => Some(Err(format!("agent get_totp failed: {}", explain(&e)))),
        }
    })
    .flatten()
}

/// Refresh the TOTP for a known entry id. Used by the `--watch` loop to avoid
/// re-running search every tick. Same three-state semantics: `None` means the
/// agent stopped being routable (e.g. it locked or shut down), and the caller
/// should exit the loop.
pub fn route_get_totp_for_id(vault_path: &Path, id: Uuid) -> Option<Result<TotpView, String>> {
    let socket = paths::agent_socket_path().ok()?;
    route_get_totp_for_id_at(&socket, vault_path, id)
}

pub(crate) fn route_get_totp_for_id_at(
    socket: &Path,
    vault_path: &Path,
    id: Uuid,
) -> Option<Result<TotpView, String>> {
    let socket = socket.to_path_buf();
    let vault_path = vault_path.to_path_buf();
    run_async(async move {
        let mut client = AgentClient::connect(&socket).await.ok()?;
        if !is_unlocked_for_vault(&mut client, &vault_path).await {
            return None;
        }
        match client.get_totp(id).await {
            Ok(view) => Some(Ok(view)),
            Err(ClientError::Agent(ae)) if ae.code == ErrorCode::VaultLocked => None,
            Err(e) => Some(Err(format!("agent get_totp failed: {}", explain(&e)))),
        }
    })
    .flatten()
}

/// Fetch a full entry by id via a running agent. Companion to
/// [`route_list_filtered`] for flows that pick a summary locally and then
/// need the full record (e.g. `vaultic search`). Same three-state return
/// semantics as the other route helpers.
pub fn route_get_entry_by_id(vault_path: &Path, id: Uuid) -> Option<Result<VaultEntry, String>> {
    let socket = paths::agent_socket_path().ok()?;
    route_get_entry_by_id_at(&socket, vault_path, id)
}

pub(crate) fn route_get_entry_by_id_at(
    socket: &Path,
    vault_path: &Path,
    id: Uuid,
) -> Option<Result<VaultEntry, String>> {
    let socket = socket.to_path_buf();
    let vault_path = vault_path.to_path_buf();
    run_async(async move {
        let mut client = AgentClient::connect(&socket).await.ok()?;
        if !is_unlocked_for_vault(&mut client, &vault_path).await {
            return None;
        }
        match client.get_entry(id).await {
            Ok(entry) => Some(Ok(entry)),
            Err(ClientError::Agent(ae)) if ae.code == ErrorCode::VaultLocked => None,
            Err(e) => Some(Err(format!("agent get_entry failed: {}", explain(&e)))),
        }
    })
    .flatten()
}

/// Read-through filtered list via a running agent. Same three-state return
/// semantics as the other route helpers: `None` means the agent isn't
/// routable (caller should fall back to local sled), `Some(Ok)` is the
/// summaries, `Some(Err)` is a user-visible failure that happened after
/// we'd already committed to the agent path.
pub fn route_list_filtered(
    vault_path: &Path,
    filter: SearchFilter,
) -> Option<Result<Vec<EntrySummary>, String>> {
    let socket = paths::agent_socket_path().ok()?;
    route_list_filtered_at(&socket, vault_path, filter)
}

pub(crate) fn route_list_filtered_at(
    socket: &Path,
    vault_path: &Path,
    filter: SearchFilter,
) -> Option<Result<Vec<EntrySummary>, String>> {
    let socket = socket.to_path_buf();
    let vault_path = vault_path.to_path_buf();
    run_async(async move {
        let mut client = AgentClient::connect(&socket).await.ok()?;
        if !is_unlocked_for_vault(&mut client, &vault_path).await {
            return None;
        }
        match client.list_filtered(filter).await {
            Ok(list) => Some(Ok(list)),
            Err(ClientError::Agent(ae)) if ae.code == ErrorCode::VaultLocked => None,
            Err(e) => Some(Err(format!("agent list_filtered failed: {}", explain(&e)))),
        }
    })
    .flatten()
}

/// True only if this client's daemon is currently unlocked AND its open vault
/// path matches `expected`. A prerequisite for any read-through routing.
async fn is_unlocked_for_vault(client: &mut AgentClient, expected: &Path) -> bool {
    let status = match client.status().await {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !status.unlocked {
        return false;
    }
    match status.vault_path.as_deref() {
        Some(p) => Path::new(p) == expected,
        None => false,
    }
}

/// Compact, user-friendly rendering of a `ClientError`. Maps the typed agent
/// error codes onto short phrases that read well in CLI output. Falls through
/// to the daemon's raw message for anything we don't have a special override
/// for — those messages already carry the entry id and reason (e.g. "entry
/// {id} has no totp_secret", which the agent collapses into the `NotFound`
/// code alongside truly-missing entries).
fn explain(e: &ClientError) -> String {
    match e {
        ClientError::Agent(ae) => match ae.code {
            ErrorCode::VaultLocked => "agent is locked (try `vaultic unlock` again)".to_string(),
            ErrorCode::BadKey => "agent could not unwrap the vault".to_string(),
            _ => ae.message.clone(),
        },
        _ => e.to_string(),
    }
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

    #[test]
    fn explain_maps_locked_to_friendly_message() {
        let e = ClientError::Agent(crate::agent::protocol::AgentError {
            code: ErrorCode::VaultLocked,
            message: "vault is locked".to_string(),
        });
        let msg = explain(&e);
        assert!(msg.contains("agent is locked"), "got: {}", msg);
    }

    #[test]
    fn explain_passes_through_agent_message_for_not_found() {
        // Agent's NotFound covers both "entry deleted" and "entry has no
        // totp_secret"; surface its full message so the user can tell which.
        let e = ClientError::Agent(crate::agent::protocol::AgentError {
            code: ErrorCode::NotFound,
            message: "entry abc has no totp_secret".to_string(),
        });
        let msg = explain(&e);
        assert!(msg.contains("totp_secret"), "got: {}", msg);
    }

    #[test]
    fn route_get_entry_at_socket_unreachable_returns_none() {
        // No daemon listening at this path; route helper must say "not
        // routable" rather than blow up.
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("nope.sock");
        let vault = dir.path().join("vault");
        let result = route_get_entry_at(&socket, &vault, "anything", |_| -> Option<usize> {
            Some(0)
        });
        assert!(result.is_none());
    }

    #[test]
    fn route_get_totp_for_id_at_socket_unreachable_returns_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("nope.sock");
        let vault = dir.path().join("vault");
        let result = route_get_totp_for_id_at(&socket, &vault, Uuid::nil());
        assert!(result.is_none());
    }

    /// End-to-end exercise of `route_get_entry_at` and `route_get_totp_at`:
    /// boot a daemon, populate a vault, unlock the daemon, run the helpers
    /// against a temp socket. Mirrors the harness in
    /// `tests/agent_integration.rs` but kept inline so we don't have to lift
    /// internal helpers into the public API for testability.
    mod end_to_end {
        use super::*;
        use crate::agent::{serve, ServerConfig};
        use crate::models::{EntryType, KdfParams, SensitiveString, VaultEntry};
        use crate::storage::VaultStorage;
        use std::time::Duration;
        use tempfile::TempDir;
        use tokio::net::UnixStream;
        use tokio::sync::mpsc;

        const TEST_KEY: [u8; 32] = [0x77; 32];

        struct Harness {
            _vault_dir: TempDir,
            _socket_dir: TempDir,
            vault_path: PathBuf,
            socket_path: PathBuf,
            sample_entry_id: Uuid,
            totp_entry_id: Uuid,
            shutdown_tx: mpsc::Sender<()>,
        }

        async fn boot() -> Harness {
            let vault_dir = TempDir::new().unwrap();
            let socket_dir = TempDir::new().unwrap();
            let vault_path = vault_dir.path().join("vault");
            let socket_path = socket_dir.path().join("agent.sock");

            let key = crate::crypto::MasterKey::from_bytes(TEST_KEY);
            let mut storage = VaultStorage::create(
                &vault_path,
                "route-test",
                &key,
                KdfParams::default(),
                "test-owner".to_string(),
            )
            .unwrap();

            let mut entry = VaultEntry::new("GitHub", EntryType::Password);
            entry.username = Some("octocat@example.com".to_string());
            entry.password = Some(SensitiveString::new("hunter2"));
            let sample_entry_id = entry.id;
            storage.add_entry(&entry).unwrap();

            // Distinct name so a search for "MyAuthenticator" matches only
            // this entry — no fuzzy collision with "GitHub" above.
            let mut totp_entry = VaultEntry::new("MyAuthenticator", EntryType::Totp);
            totp_entry.totp_secret = Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string()));
            let totp_entry_id = totp_entry.id;
            storage.add_entry(&totp_entry).unwrap();

            drop(storage);

            let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
            let cfg = ServerConfig {
                socket_path: socket_path.clone(),
                inactivity_timeout: Duration::from_secs(900),
            };
            tokio::spawn(async move {
                let _ = serve(cfg, shutdown_rx).await;
            });
            for _ in 0..50 {
                if UnixStream::connect(&socket_path).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            Harness {
                _vault_dir: vault_dir,
                _socket_dir: socket_dir,
                vault_path,
                socket_path,
                sample_entry_id,
                totp_entry_id,
                shutdown_tx,
            }
        }

        async fn unlock(socket: &Path, vault_path: &Path) {
            let mut client = AgentClient::connect(socket).await.unwrap();
            client
                .unlock(vault_path.display().to_string(), hex_encode(&TEST_KEY))
                .await
                .unwrap();
        }

        // The route helpers are sync; spawn_blocking lets us call them from
        // inside a tokio test without nesting runtimes.
        async fn run_blocking<F, T>(f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            tokio::task::spawn_blocking(f).await.unwrap()
        }

        #[tokio::test]
        async fn route_get_entry_returns_none_when_locked() {
            let h = boot().await;
            // Daemon is running but never unlocked. Must report not-routable.
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result = run_blocking(move || {
                route_get_entry_at(&socket, &vault, "github", |_| -> Option<usize> {
                    panic!("pick should not be called when not routable")
                })
            })
            .await;
            assert!(result.is_none(), "expected None, got {:?}", result);
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_entry_returns_none_when_different_vault() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            // Caller asks about a different vault path. Routing must refuse.
            let socket = h.socket_path.clone();
            let other = h.vault_path.parent().unwrap().join("other");
            let result = run_blocking(move || {
                route_get_entry_at(&socket, &other, "github", |_| -> Option<usize> {
                    panic!("pick should not be called when not routable")
                })
            })
            .await;
            assert!(result.is_none());
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_entry_fetches_unique_match() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let expected_id = h.sample_entry_id;
            let result = run_blocking(move || {
                route_get_entry_at(&socket, &vault, "octocat", |_| -> Option<usize> { Some(0) })
            })
            .await;
            match result {
                Some(Ok(entry)) => {
                    assert_eq!(entry.id, expected_id);
                    assert_eq!(entry.name, "GitHub");
                }
                other => panic!("expected Some(Ok(entry)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_entry_no_match_surfaces_error() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result = run_blocking(move || {
                route_get_entry_at(&socket, &vault, "no-such-entry-xyz", |_| -> Option<usize> {
                    Some(0)
                })
            })
            .await;
            match result {
                Some(Err(msg)) => assert!(msg.contains("No entry found"), "got: {}", msg),
                other => panic!("expected Some(Err(_)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_totp_at_returns_view() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let expected_id = h.totp_entry_id;
            let result = run_blocking(move || {
                route_get_totp_at(&socket, &vault, "MyAuthenticator", |_| -> Option<usize> {
                    Some(0)
                })
            })
            .await;
            match result {
                Some(Ok((id, name, view))) => {
                    assert_eq!(id, expected_id);
                    assert_eq!(name, "MyAuthenticator");
                    assert_eq!(view.code.len(), 6);
                    assert_eq!(view.period_total_seconds, 30);
                }
                other => panic!("expected Some(Ok(_)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_totp_for_id_at_returns_view() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let id = h.totp_entry_id;
            let result = run_blocking(move || route_get_totp_for_id_at(&socket, &vault, id)).await;
            match result {
                Some(Ok(view)) => assert_eq!(view.code.len(), 6),
                other => panic!("expected Some(Ok(view)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_list_filtered_at_returns_all_when_filter_empty() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result =
                run_blocking(move || route_list_filtered_at(&socket, &vault, SearchFilter::new()))
                    .await;
            match result {
                Some(Ok(list)) => {
                    assert_eq!(list.len(), 2, "expected 2 summaries, got {}", list.len());
                    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
                    assert!(names.contains(&"GitHub"));
                    assert!(names.contains(&"MyAuthenticator"));
                }
                other => panic!("expected Some(Ok(_)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_list_filtered_at_applies_query() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result = run_blocking(move || {
                route_list_filtered_at(&socket, &vault, SearchFilter::new().with_query("octocat"))
            })
            .await;
            match result {
                Some(Ok(list)) => {
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].name, "GitHub");
                }
                other => panic!("expected Some(Ok(_)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_list_filtered_at_returns_none_when_locked() {
            let h = boot().await;
            // Boot without unlocking — must be not-routable.
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result =
                run_blocking(move || route_list_filtered_at(&socket, &vault, SearchFilter::new()))
                    .await;
            assert!(result.is_none(), "expected None, got {:?}", result);
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_entry_by_id_at_returns_full_entry() {
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let id = h.sample_entry_id;
            let result = run_blocking(move || route_get_entry_by_id_at(&socket, &vault, id)).await;
            match result {
                Some(Ok(entry)) => {
                    assert_eq!(entry.id, id);
                    assert_eq!(entry.name, "GitHub");
                    assert_eq!(entry.username.as_deref(), Some("octocat@example.com"));
                    assert!(entry.password.is_some());
                }
                other => panic!("expected Some(Ok(entry)), got {:?}", other),
            }
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn route_get_entry_by_id_at_returns_none_when_locked() {
            let h = boot().await;
            // No unlock; not routable.
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let id = h.sample_entry_id;
            let result = run_blocking(move || route_get_entry_by_id_at(&socket, &vault, id)).await;
            assert!(result.is_none());
            let _ = h.shutdown_tx.send(()).await;
        }

        #[tokio::test]
        async fn entry_summary_carries_extended_fields() {
            // Lock the wire format down: Type / Strength / Last Used columns
            // depend on these.
            let h = boot().await;
            unlock(&h.socket_path, &h.vault_path).await;
            let socket = h.socket_path.clone();
            let vault = h.vault_path.clone();
            let result =
                run_blocking(move || route_list_filtered_at(&socket, &vault, SearchFilter::new()))
                    .await;
            let list = result.unwrap().unwrap();
            let github = list.iter().find(|s| s.name == "GitHub").unwrap();
            assert_eq!(github.entry_type, EntryType::Password);
            // password_strength is never set anywhere in the codebase yet,
            // so it round-trips as None — we just need the field to exist.
            assert!(github.password_strength.is_none());
            // last_accessed isn't set on add either; confirm it serializes.
            assert!(github.last_accessed.is_none());
            let _ = h.shutdown_tx.send(()).await;
        }
    }
}
