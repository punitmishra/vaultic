//! `vaultic-agent` server: bind a Unix socket, authenticate peer credentials,
//! dispatch protocol methods, drive the inactivity timer, shut down cleanly.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::agent::paths;
use crate::agent::protocol::{
    read_frame_async, write_frame_async, AgentError, ErrorCode, Event, Frame, FramingError, Method,
    PongView, Request, Response, ResponseBody, PROTOCOL_VERSION,
};
use crate::agent::state::{AgentState, StateError};

/// Errors raised at server startup. Per-connection errors are handled
/// inline (we just log and drop the connection).
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not resolve socket path: {0}")]
    Path(#[from] paths::PathError),

    #[error("another vaultic-agent is already running on {0}")]
    AlreadyRunning(PathBuf),
}

/// Configuration for the daemon. Defaults match the existing CLI session
/// timeout (15 min).
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub inactivity_timeout: Duration,
}

impl ServerConfig {
    /// Build a config with the OS-default socket path and 15-min timeout.
    pub fn defaults() -> Result<Self, paths::PathError> {
        Ok(Self {
            socket_path: paths::agent_socket_path()?,
            inactivity_timeout: crate::agent::state::DEFAULT_INACTIVITY_TIMEOUT,
        })
    }
}

/// Run the daemon until `shutdown_rx` fires (SIGINT, `Method::Shutdown`,
/// or test harness signal). Returns when the listener has been dropped
/// and the socket file unlinked.
pub async fn serve(
    config: ServerConfig,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<(), ServerError> {
    let listener = bind_listener(&config.socket_path).await?;
    set_socket_permissions(&config.socket_path)?;

    let state = AgentState::with_timeout(config.inactivity_timeout);
    let event_bus = EventBus::new();
    let inactivity_task = spawn_inactivity_watch(state.clone(), event_bus.clone());

    let (internal_shutdown_tx, mut internal_shutdown_rx) = mpsc::channel::<()>(1);

    let accept_loop = tokio::spawn(accept_loop(
        listener,
        state.clone(),
        event_bus.clone(),
        internal_shutdown_tx.clone(),
    ));

    tokio::select! {
        _ = shutdown_rx.recv() => {}
        _ = internal_shutdown_rx.recv() => {}
        _ = accept_loop => {} // listener died
    }

    // Tell every connected client we're going away.
    event_bus.broadcast(Event::Shutdown).await;

    // Best-effort cleanup. Ignore errors here; the daemon is going away.
    let _ = tokio::fs::remove_file(&config.socket_path).await;
    inactivity_task.abort();

    Ok(())
}

/// Bind the socket, handling stale leftovers from a previous crashed daemon.
async fn bind_listener(socket_path: &Path) -> Result<UnixListener, ServerError> {
    if let Some(parent) = socket_path.parent() {
        let already_exists = parent.exists();
        tokio::fs::create_dir_all(parent).await?;
        // Only chmod the directory if WE just created it. Tightening
        // permissions on an existing directory could fail with EPERM (e.g.
        // /tmp is system-owned) and is the user's responsibility anyway.
        if !already_exists {
            // Best-effort: if even our own newly-created dir refuses chmod,
            // continue rather than fail the whole start-up. The socket file
            // permissions below are the meaningful boundary.
            let _ = set_dir_permissions(parent);
        }
    }

    if socket_path.exists() {
        // Try to connect. If the existing socket is alive, refuse to start.
        // If it's a stale leftover (ECONNREFUSED), unlink it and rebind.
        match UnixStream::connect(socket_path).await {
            Ok(_) => return Err(ServerError::AlreadyRunning(socket_path.to_path_buf())),
            Err(_) => {
                // ECONNREFUSED / ENOENT / etc. — assume stale.
                tokio::fs::remove_file(socket_path).await.ok();
            }
        }
    }

    Ok(UnixListener::bind(socket_path)?)
}

#[cfg(unix)]
fn set_socket_permissions(socket_path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(socket_path, perms)
}

#[cfg(unix)]
fn set_dir_permissions(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
fn set_socket_permissions(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Accept loop. Each accepted connection is checked against peer
/// credentials and then handed off to its own task.
async fn accept_loop(
    listener: UnixListener,
    state: Arc<AgentState>,
    event_bus: EventBus,
    shutdown_tx: mpsc::Sender<()>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                if !is_authorized_peer(&stream) {
                    drop(stream); // closes the connection silently
                    continue;
                }
                let state = state.clone();
                let bus = event_bus.clone();
                let stop = shutdown_tx.clone();
                tokio::spawn(async move {
                    handle_connection(stream, state, bus, stop).await;
                });
            }
            Err(e) => {
                // Listener errors are fatal in practice (closed listener,
                // descriptor exhausted). Stop the accept loop; `serve()`
                // will tear down on the listener-died select arm.
                tracing::warn!(?e, "accept error, stopping accept loop");
                return;
            }
        }
    }
}

/// Same-UID-only peer authentication. Cross-platform via tokio's
/// `peer_cred`, which wraps `SO_PEERCRED` on Linux and `getpeereid()`
/// on macOS.
fn is_authorized_peer(stream: &UnixStream) -> bool {
    let cred = match stream.peer_cred() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let own_uid = own_uid();
    cred.uid() == own_uid
}

#[cfg(unix)]
fn own_uid() -> u32 {
    // SAFETY: getuid is async-signal-safe and never fails.
    unsafe { libc_getuid() }
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    // Avoid pulling in libc as a direct dep; the symbol is provided by
    // libc on every Unix.
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

#[cfg(not(unix))]
fn own_uid() -> u32 {
    0
}

/// Single-connection request loop. One frame in, one frame out, until the
/// peer disconnects, sends a malformed frame, or the daemon shuts down.
async fn handle_connection(
    stream: UnixStream,
    state: Arc<AgentState>,
    event_bus: EventBus,
    shutdown_tx: mpsc::Sender<()>,
) {
    let (mut reader, write_half) = stream.into_split();
    // Shared so the request loop and the event-pump task can both write
    // frames back to the client without stepping on each other.
    let write_handle = Arc::new(Mutex::new(write_half));

    // Subscribe this connection to events so it gets `SessionExpired` /
    // `Shutdown` pushes.
    let mut event_rx = event_bus.subscribe();
    let event_writer = write_handle.clone();
    let event_pump = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let frame = Frame::Event(event);
            let mut guard = event_writer.lock().await;
            if write_frame_async(&mut *guard, &frame).await.is_err() {
                break;
            }
        }
    });

    loop {
        let frame = match read_frame_async(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,                 // peer disconnected cleanly
            Err(FramingError::Io(_)) => break, // peer hung up mid-frame; drop
            Err(other) => {
                // Bad framing / oversized / invalid JSON. Send one final
                // error response on a synthetic id and drop the connection.
                let response = Frame::Response(Response {
                    id: uuid::Uuid::nil(),
                    body: ResponseBody::Error(AgentError {
                        code: ErrorCode::Ipc,
                        message: other.to_string(),
                    }),
                });
                let mut guard = write_handle.lock().await;
                let _ = write_frame_async(&mut *guard, &response).await;
                break;
            }
        };

        let request = match frame {
            Frame::Request(req) => req,
            // Clients only send Request frames. Anything else is a protocol
            // violation; treat it like a bad frame.
            _ => break,
        };

        let id = request.id;
        let is_shutdown = matches!(request.method, Method::Shutdown);
        let response = dispatch(&state, request).await;
        let response_frame = Frame::Response(Response { id, body: response });

        {
            let mut guard = write_handle.lock().await;
            if write_frame_async(&mut *guard, &response_frame)
                .await
                .is_err()
            {
                break;
            }
        }

        if is_shutdown {
            // Tell the supervisor to stop accepting new connections + tear
            // everything down. Dropping send error: the supervisor may have
            // already started shutting down; that's fine.
            let _ = shutdown_tx.send(()).await;
        }
    }

    event_pump.abort();
}

/// Map a single `Method` invocation to a `ResponseBody`. The dispatcher is
/// pure data-in / data-out — no IO of its own.
async fn dispatch(state: &Arc<AgentState>, request: Request) -> ResponseBody {
    match request.method {
        Method::Ping => ok_value(serde_json::to_value(PongView {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        })),

        Method::Status => ok_value(serde_json::to_value(state.status().await)),

        Method::Unlock {
            vault_path,
            derived_key_hex,
        } => match state
            .unlock(PathBuf::from(vault_path), &derived_key_hex)
            .await
        {
            Ok(()) => ok_value(serde_json::to_value(serde_json::json!({"unlocked": true}))),
            Err(e) => err_for(&e),
        },

        Method::Lock => {
            state.lock().await;
            ok_value(serde_json::to_value(serde_json::json!({"locked": true})))
        }

        Method::ListSummary => match state.list_summary().await {
            Ok(list) => ok_value(serde_json::to_value(list)),
            Err(e) => err_for(&e),
        },

        Method::GetEntry { id } => match state.get_entry(id).await {
            Ok(entry) => ok_value(serde_json::to_value(entry)),
            Err(e) => err_for(&e),
        },

        Method::GetTotp { id } => match state.get_totp(id).await {
            Ok(view) => ok_value(serde_json::to_value(view)),
            Err(e) => err_for(&e),
        },

        Method::Search { query } => match state.search(&query).await {
            Ok(list) => ok_value(serde_json::to_value(list)),
            Err(e) => err_for(&e),
        },

        Method::Shutdown => ok_value(serde_json::to_value(
            serde_json::json!({"shutting_down": true}),
        )),
    }
}

fn ok_value(v: Result<serde_json::Value, serde_json::Error>) -> ResponseBody {
    match v {
        Ok(v) => ResponseBody::Result(v),
        Err(e) => ResponseBody::Error(AgentError {
            code: ErrorCode::VaultIo,
            message: format!("serialization: {}", e),
        }),
    }
}

fn err_for(e: &StateError) -> ResponseBody {
    let code = match e {
        StateError::Locked => ErrorCode::VaultLocked,
        StateError::NotFound(_) | StateError::NoTotpSecret(_) => ErrorCode::NotFound,
        StateError::BadKey | StateError::BadKeyLength(_) | StateError::InvalidHex(_) => {
            ErrorCode::BadKey
        }
        StateError::VaultIo(_) => ErrorCode::VaultIo,
    };
    ResponseBody::Error(AgentError {
        code,
        message: e.to_string(),
    })
}

// ============ Inactivity watch ============

fn spawn_inactivity_watch(state: Arc<AgentState>, event_bus: EventBus) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if state.is_expired().await {
                state.lock().await;
                event_bus.broadcast(Event::SessionExpired).await;
            }
        }
    })
}

// ============ Event bus ============

/// A tiny fan-out: the daemon broadcasts events to every active connection.
/// Each connection holds a receiver via `subscribe()`. Lossy on slow
/// receivers (channel uses bounded buffer; we drop on backpressure rather
/// than block the broadcaster).
#[derive(Clone)]
struct EventBus {
    subs: Arc<Mutex<Vec<mpsc::Sender<Event>>>>,
}

impl EventBus {
    fn new() -> Self {
        Self {
            subs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn subscribe(&self) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        // Best-effort: lock and push. If we're under contention there's no
        // ordering guarantee with broadcast(), but that's fine for events.
        let subs = self.subs.clone();
        tokio::spawn(async move {
            subs.lock().await.push(tx);
        });
        rx
    }

    async fn broadcast(&self, event: Event) {
        let mut subs = self.subs.lock().await;
        subs.retain(|tx| !tx.is_closed());
        for tx in subs.iter() {
            let _ = tx.try_send(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::protocol::{ErrorCode, Method, Request};
    use uuid::Uuid;

    #[tokio::test]
    async fn dispatch_status_when_locked_succeeds() {
        let state = AgentState::new();
        let req = Request {
            id: Uuid::nil(),
            method: Method::Status,
        };
        let body = dispatch(&state, req).await;
        match body {
            ResponseBody::Result(v) => assert_eq!(v["unlocked"], false),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[tokio::test]
    async fn dispatch_list_when_locked_returns_vault_locked() {
        let state = AgentState::new();
        let req = Request {
            id: Uuid::nil(),
            method: Method::ListSummary,
        };
        let body = dispatch(&state, req).await;
        match body {
            ResponseBody::Error(AgentError { code, .. }) => {
                assert_eq!(code, ErrorCode::VaultLocked)
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[tokio::test]
    async fn dispatch_ping_returns_protocol_version() {
        let state = AgentState::new();
        let req = Request {
            id: Uuid::nil(),
            method: Method::Ping,
        };
        let body = dispatch(&state, req).await;
        match body {
            ResponseBody::Result(v) => {
                assert_eq!(v["protocol_version"], PROTOCOL_VERSION);
                assert!(v["agent_version"].is_string());
            }
            other => panic!("unexpected: {:?}", other),
        }
    }
}
