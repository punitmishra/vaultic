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
use uuid::Uuid;

use crate::agent::client::{AgentClient, ClientError};
use crate::agent::keys;
use crate::agent::protocol::{EntrySummary, PongView, StatusView, TotpView};
use crate::models::VaultEntry;

/// Things the GUI asks the worker to do.
#[derive(Debug)]
pub enum Command {
    /// Re-issue ping + status. Sent on a 5s timer and on user clicks.
    RefreshStatus,
    /// Run KDF locally, then send `Method::Unlock` to the agent.
    Unlock {
        vault_path: PathBuf,
        password: String,
    },
    /// Send `Method::Lock`.
    Lock,
    /// Send `Method::ListSummary` and report the result.
    LoadEntries,
    /// Send `Method::GetEntry` for the given id.
    LoadEntry { id: Uuid },
    /// Send `Method::Search` with the supplied query and report the result.
    Search { query: String },
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
    /// Unlock attempt finished. Either succeeded or returned an error
    /// message suitable for inline display in the unlock form.
    UnlockResult(Result<(), String>),
    /// Result of `Method::ListSummary`.
    Entries(Vec<EntrySummary>),
    /// Result of `Method::Search`.
    SearchResults(Vec<EntrySummary>),
    /// Result of `Method::GetEntry`.
    Entry(Box<VaultEntry>),
    /// Result of `Method::GetTotp`.
    Totp { id: Uuid, view: TotpView },
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
            // Use a separate short-lived client so we don't fight the main
            // request stream when both happen to fire at once.
            let mut local: Option<AgentClient> = None;
            let _ = handle(&timer_socket, &mut local, &timer_tx, Command::RefreshStatus).await;
            timer_ctx.request_repaint();
        }
    });

    // std mpsc isn't async-friendly; spawn_blocking pumps it into a tokio
    // mpsc that this task can `recv()` cleanly.
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
                // Surface a reasonable per-command failure event. For
                // Unlock specifically we want the form to learn that the
                // attempt didn't even reach the agent.
                let reason = format!("connect: {}", e);
                if matches!(cmd, Command::Unlock { .. }) {
                    let _ = event_tx.send(Event::UnlockResult(Err(reason)));
                } else {
                    let _ = event_tx.send(Event::Offline { reason });
                }
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
            Err(e) => report_call_failure(client, event_tx, "ping/status", e),
        },
        Command::Unlock {
            vault_path,
            mut password,
        } => {
            let result = unlock_flow(c, &vault_path, &password).await;
            // Zero the password copy in this stack frame as soon as we're
            // done with it. The original String in Command was already
            // moved here.
            password.replace_range(.., "");
            match result {
                Ok(()) => {
                    let _ = event_tx.send(Event::UnlockResult(Ok(())));
                    // Refresh status so the UI sees the unlocked state
                    // without a 5s wait.
                    if let Ok((pong, status)) = refresh_status(c).await {
                        let _ = event_tx.send(Event::Pong { pong, status });
                    }
                    // And populate the entries list immediately.
                    if let Ok(entries) = c.list_summary().await {
                        let _ = event_tx.send(Event::Entries(entries));
                    }
                }
                Err(reason) => {
                    let _ = event_tx.send(Event::UnlockResult(Err(reason)));
                }
            }
        }
        Command::Lock => {
            if let Err(e) = c.lock().await {
                report_call_failure(client, event_tx, "lock", e);
            } else if let Ok((pong, status)) = refresh_status(c).await {
                let _ = event_tx.send(Event::Pong { pong, status });
            }
        }
        Command::LoadEntries => match c.list_summary().await {
            Ok(entries) => {
                let _ = event_tx.send(Event::Entries(entries));
            }
            Err(e) => report_call_failure(client, event_tx, "list", e),
        },
        Command::LoadEntry { id } => match c.get_entry(id).await {
            Ok(entry) => {
                let _ = event_tx.send(Event::Entry(Box::new(entry)));
            }
            Err(e) => report_call_failure(client, event_tx, "get_entry", e),
        },
        Command::Search { query } => match c.search(query).await {
            Ok(results) => {
                let _ = event_tx.send(Event::SearchResults(results));
            }
            Err(e) => report_call_failure(client, event_tx, "search", e),
        },
        Command::Quit => unreachable!(),
    }
}

/// Run KDF + send `Method::Unlock`. Maps every failure into a string suitable
/// for inline display in the unlock form, with the most useful prefix
/// (kdf / agent / connect / etc.) in front.
async fn unlock_flow(
    client: &mut AgentClient,
    vault_path: &std::path::Path,
    password: &str,
) -> Result<(), String> {
    let derived = match keys::derive_for_unlock(vault_path, password) {
        Ok(d) => d,
        Err(e) => return Err(format!("kdf: {}", e)),
    };
    let hex = derived.into_hex();
    match client.unlock(vault_path.display().to_string(), hex).await {
        Ok(()) => Ok(()),
        Err(ClientError::Agent(ae)) => Err(ae.message),
        Err(other) => Err(format!("agent: {}", other)),
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
