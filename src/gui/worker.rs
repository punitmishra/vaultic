//! Tokio worker that owns the `AgentClient` and bridges egui's sync world
//! to the agent's async one.
//!
//! Spawned once at startup. Reads `Command`s from a sync mpsc channel,
//! writes `Event`s back, and asks the egui context to repaint after every
//! event so the UI doesn't have to poll.
//!
//! Reconnect strategy: best-effort. When a call fails, we drop the client
//! and the next command tries to reconnect. On a cold "agent isn't running",
//! `connect` returns ConnectionRefused/NotFound and we report it as
//! `Event::Offline`.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui;

use crate::agent::client::{AgentClient, ClientError};
use crate::agent::protocol::{PongView, StatusView};

/// Things the GUI asks the worker to do.
#[derive(Debug)]
pub enum Command {
    /// Re-issue ping + status. Sent on a 5s timer and on user clicks.
    RefreshStatus,
    /// Send `Method::Lock`.
    Lock,
    /// Stop the worker (graceful shutdown).
    Quit,
}

/// Things the worker reports to the GUI.
#[derive(Debug)]
pub enum Event {
    /// Agent answered ping + status. The GUI replaces its cached state.
    Pong { pong: PongView, status: StatusView },
    /// Connect or call failed. The reason is suitable for inline display.
    Offline { reason: String },
}

/// Spawn the worker on the supplied tokio runtime. Returns immediately.
pub fn spawn(
    runtime: &tokio::runtime::Runtime,
    socket_path: PathBuf,
    egui_ctx: egui::Context,
    cmd_rx: mpsc::Receiver<Command>,
    event_tx: mpsc::Sender<Event>,
) {
    runtime.spawn(async move {
        run(socket_path, egui_ctx, cmd_rx, event_tx).await;
    });
}

async fn run(
    socket_path: PathBuf,
    egui_ctx: egui::Context,
    cmd_rx: mpsc::Receiver<Command>,
    event_tx: mpsc::Sender<Event>,
) {
    // Hold one client across requests. On error, drop it; the next command
    // will reconnect.
    let mut client: Option<AgentClient> = None;

    // Drive the first refresh ourselves so the GUI doesn't sit on
    // "Connecting..." until the user clicks something.
    let _ = handle(&socket_path, &mut client, &event_tx, Command::RefreshStatus).await;
    egui_ctx.request_repaint();

    // Background timer: kick a refresh every 5 seconds so the UI stays
    // accurate even when the user isn't interacting.
    let timer_tx = event_tx.clone();
    let timer_socket = socket_path.clone();
    let timer_ctx = egui_ctx.clone();
    let timer_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // We don't have shared access to `client` from here, so we just
            // emit a synthetic refresh by re-connecting per-tick. Cheap on
            // a Unix socket; keeps the state machine simple.
            let mut local: Option<AgentClient> = None;
            let _ = handle(&timer_socket, &mut local, &timer_tx, Command::RefreshStatus).await;
            timer_ctx.request_repaint();
        }
    });

    // Synchronous mpsc means we can't `recv()` directly inside an async fn
    // without blocking the executor. Spawn-blocking trick: a small task
    // converts sync recv -> async tokio mpsc.
    let (a_cmd_tx, mut a_cmd_rx) = tokio::sync::mpsc::channel::<Command>(8);
    let pump = tokio::task::spawn_blocking(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            if a_cmd_tx.blocking_send(cmd).is_err() {
                break;
            }
        }
    });

    while let Some(cmd) = a_cmd_rx.recv().await {
        let quitting = matches!(cmd, Command::Quit);
        let _ = handle(&socket_path, &mut client, &event_tx, cmd).await;
        egui_ctx.request_repaint();
        if quitting {
            break;
        }
    }

    timer_handle.abort();
    let _ = pump.await;
}

async fn handle(
    socket_path: &PathBuf,
    client: &mut Option<AgentClient>,
    event_tx: &mpsc::Sender<Event>,
    cmd: Command,
) {
    if matches!(cmd, Command::Quit) {
        return;
    }

    if client.is_none() {
        match AgentClient::connect(socket_path).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                let _ = event_tx.send(Event::Offline {
                    reason: format!("connect: {}", e),
                });
                return;
            }
        }
    }

    let c = client.as_mut().expect("just connected above");

    match cmd {
        Command::RefreshStatus => match refresh_status(c).await {
            Ok((pong, status)) => {
                let _ = event_tx.send(Event::Pong { pong, status });
            }
            Err(e) => {
                report_call_failure(client, event_tx, "ping/status", e);
            }
        },
        Command::Lock => {
            if let Err(e) = c.lock().await {
                report_call_failure(client, event_tx, "lock", e);
            } else if let Ok((pong, status)) = refresh_status(c).await {
                let _ = event_tx.send(Event::Pong { pong, status });
            }
        }
        Command::Quit => unreachable!(),
    }
}

async fn refresh_status(client: &mut AgentClient) -> Result<(PongView, StatusView), ClientError> {
    let pong = client.ping().await?;
    let status = client.status().await?;
    Ok((pong, status))
}

fn report_call_failure(
    client: &mut Option<AgentClient>,
    event_tx: &mpsc::Sender<Event>,
    op: &str,
    err: ClientError,
) {
    // Transport failures invalidate the open client; agent-level errors
    // don't (the connection is still healthy, the call just had bad
    // semantics — though for ping/status this is unusual).
    if !matches!(err, ClientError::Agent(_)) {
        *client = None;
    }
    let _ = event_tx.send(Event::Offline {
        reason: format!("{}: {}", op, err),
    });
}
