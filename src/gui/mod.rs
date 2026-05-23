//! `vaultic-gui` — egui-based desktop app that talks to `vaultic-agent`.
//!
//! Sessions 1-3 of #9 stood up the daemon protocol, daemon, and GUI shell.
//! Session 4 (this iteration) makes the GUI actually useful: unlock flow,
//! entry list with fuzzy search, detail view with copy-to-clipboard.
//!
//! ## Threading model
//!
//! egui is immediate-mode and runs on the main thread. The agent client is
//! async tokio. We bridge them with two mpsc channels and a worker task:
//!
//! ```text
//!     egui main thread                  tokio worker
//!     ┌────────────┐  Command   ┌──────────────────┐
//!     │ VaulticGui ├───────────►│ AgentClient      │
//!     │            │            │ - ping/status    │
//!     │            │◄───────────┤ - unlock/list    │
//!     └────────────┘  Event     └──────────────────┘
//! ```
//!
//! `Command` is what the GUI asks the worker to do. `Event` is what the
//! worker reports back. The worker calls `egui::Context::request_repaint()`
//! after every event so the UI doesn't have to poll.

pub mod screens;
pub mod theme;
pub mod worker;

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use uuid::Uuid;

use crate::agent::protocol::{EntrySummary, PongView, StatusView, TotpView};
use crate::gui::theme::Theme;
use crate::gui::worker::{Command, Event};
use crate::models::VaultEntry;

/// Top-level connection state. Determines which screen to draw.
#[derive(Debug, Default)]
enum AgentView {
    /// Worker hasn't reported anything yet.
    #[default]
    Connecting,
    /// Last connect attempt couldn't reach the socket.
    Offline {
        reason: String,
        last_attempt: Instant,
    },
    /// Daemon answered. The vault may or may not be unlocked.
    Online {
        pong: PongView,
        status: StatusView,
        last_refresh: Instant,
    },
}

/// User-facing state of the unlock form. Flows linearly:
/// `Idle` → user types → `Submitting` (in flight) → either back to `Idle`
/// (with `error` populated) or up the call chain to a vault-unlocked state.
#[derive(Debug, Default)]
struct UnlockForm {
    vault_path: String,
    password: String,
    error: Option<String>,
    submitting: bool,
}

/// State that exists only when the vault is unlocked.
#[derive(Debug, Default)]
struct UnlockedState {
    /// Last list_summary or search_results result. Whichever is "current".
    entries: Vec<EntrySummary>,
    /// Current text in the search box.
    search_query: String,
    /// Last sent search query, used for debouncing.
    last_dispatched_query: String,
    /// Wallclock instant when the search box last changed; we wait
    /// `SEARCH_DEBOUNCE` before sending to the agent.
    search_pending_since: Option<Instant>,
    /// id of the currently selected entry (drives detail pane).
    selected_id: Option<Uuid>,
    /// Full entry payload for `selected_id`, if loaded.
    detail: Option<Box<VaultEntry>>,
    /// Whether the password field in the detail pane is unmasked.
    password_revealed: bool,
    /// Transient banner from a copy action.
    toast: Option<Toast>,
    /// Latest TOTP view for the selected entry (if it has a totp_secret).
    /// Refreshed every `TOTP_REFRESH_INTERVAL`.
    totp: Option<(Uuid, TotpView)>,
    /// Last time we asked the agent for a TOTP code.
    last_totp_request_at: Option<Instant>,
    /// Set true when the search box should grab focus this frame (the user
    /// pressed `/` from the list, etc.).
    focus_search_next_frame: bool,
}

#[derive(Debug)]
struct Toast {
    message: String,
    shown_at: Instant,
}

const SEARCH_DEBOUNCE: Duration = Duration::from_millis(150);
const TOAST_DURATION: Duration = Duration::from_secs(2);
const TOTP_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
/// User-visible message accompanying a Copy action so they know the
/// clipboard isn't going to hold their secret forever.
pub(crate) const COPY_TOAST_SUFFIX: &str = " · clears in 30s";

/// `eframe::App` implementation. Owns the channel ends to the tokio worker
/// and a small bag of cached state.
pub struct VaulticGui {
    cmd_tx: mpsc::Sender<Command>,
    event_rx: mpsc::Receiver<Event>,
    agent: AgentView,
    unlock: UnlockForm,
    unlocked: UnlockedState,
    socket_path_label: String,
    theme: Theme,
    /// Set true when [`VaulticGui::theme`] has changed since the last
    /// frame. Triggers a fresh `Visuals` apply on the next paint.
    theme_dirty: bool,
}

impl VaulticGui {
    /// Build the app. Caller is responsible for spawning the worker that
    /// owns the receiving end of `cmd_tx` and the sending end of `event_rx`.
    pub fn new(
        cmd_tx: mpsc::Sender<Command>,
        event_rx: mpsc::Receiver<Event>,
        socket_path_label: String,
        theme_name: &str,
    ) -> Self {
        let theme = Theme::from_name(theme_name).unwrap_or_default();
        Self {
            cmd_tx,
            event_rx,
            agent: AgentView::Connecting,
            unlock: UnlockForm {
                vault_path: default_vault_path().display().to_string(),
                ..Default::default()
            },
            unlocked: UnlockedState::default(),
            socket_path_label,
            theme,
            theme_dirty: true,
        }
    }

    /// Switch to a different theme by name. No-op if the name is unknown.
    pub(crate) fn set_theme_by_name(&mut self, name: &str) {
        if let Some(theme) = Theme::from_name(name) {
            self.theme = theme;
            self.theme_dirty = true;
        }
    }

    /// Read access for draw fns.
    pub(crate) fn theme(&self) -> &Theme {
        &self.theme
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                Event::Pong { pong, status } => {
                    let was_unlocked =
                        matches!(&self.agent, AgentView::Online { status, .. } if status.unlocked);
                    let now_unlocked = status.unlocked;
                    self.agent = AgentView::Online {
                        pong,
                        status,
                        last_refresh: Instant::now(),
                    };
                    // First time we see "unlocked", populate entries.
                    if now_unlocked && !was_unlocked {
                        let _ = self.cmd_tx.send(Command::LoadEntries);
                    }
                    // First time we see "locked again", clear the
                    // unlocked-only state.
                    if was_unlocked && !now_unlocked {
                        self.unlocked = UnlockedState::default();
                    }
                }
                Event::Offline { reason } => {
                    self.agent = AgentView::Offline {
                        reason,
                        last_attempt: Instant::now(),
                    };
                }
                Event::UnlockResult(Ok(())) => {
                    self.unlock.submitting = false;
                    self.unlock.password.clear();
                    self.unlock.error = None;
                }
                Event::UnlockResult(Err(reason)) => {
                    self.unlock.submitting = false;
                    self.unlock.error = Some(reason);
                }
                Event::Entries(entries) | Event::SearchResults(entries) => {
                    self.unlocked.entries = entries;
                    // Drop selection if it's no longer in the visible list.
                    if let Some(sel) = self.unlocked.selected_id {
                        if !self.unlocked.entries.iter().any(|e| e.id == sel) {
                            self.unlocked.selected_id = None;
                            self.unlocked.detail = None;
                        }
                    }
                }
                Event::Entry(entry) => {
                    if Some(entry.id) == self.unlocked.selected_id {
                        self.unlocked.detail = Some(entry);
                        self.unlocked.password_revealed = false;
                        // Drop any stale TOTP — we may have just selected
                        // a non-TOTP entry, or the secret could be a new
                        // one; let the timer refresh from scratch.
                        self.unlocked.totp = None;
                        self.unlocked.last_totp_request_at = None;
                    }
                }
                Event::Totp { id, view } => {
                    // Only keep if it matches the currently-selected entry
                    // (otherwise the user moved on while it was in flight).
                    if Some(id) == self.unlocked.selected_id {
                        self.unlocked.totp = Some((id, view));
                    }
                }
            }
        }
    }

    /// Send a search command if the search box has been quiet for at least
    /// `SEARCH_DEBOUNCE`. Called on every frame, cheap when nothing's
    /// pending.
    fn pump_search_debounce(&mut self) {
        let pending = match self.unlocked.search_pending_since {
            Some(t) => t,
            None => return,
        };
        if pending.elapsed() < SEARCH_DEBOUNCE {
            return;
        }
        self.unlocked.search_pending_since = None;

        let query = self.unlocked.search_query.trim().to_string();
        if query == self.unlocked.last_dispatched_query {
            return;
        }
        self.unlocked.last_dispatched_query = query.clone();

        if query.is_empty() {
            let _ = self.cmd_tx.send(Command::LoadEntries);
        } else {
            let _ = self.cmd_tx.send(Command::Search { query });
        }
    }

    /// Expire the toast banner once `TOAST_DURATION` has elapsed.
    fn pump_toast(&mut self) {
        if let Some(t) = &self.unlocked.toast {
            if t.shown_at.elapsed() >= TOAST_DURATION {
                self.unlocked.toast = None;
            }
        }
    }

    /// If the selected entry has a TOTP secret, request a fresh code from
    /// the agent every `TOTP_REFRESH_INTERVAL`. Cheap when no TOTP entry
    /// is selected.
    fn pump_totp(&mut self) {
        let id = match self.unlocked.selected_id {
            Some(id) => id,
            None => return,
        };
        let needs_totp = self
            .unlocked
            .entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.has_totp)
            .unwrap_or(false);
        if !needs_totp {
            return;
        }
        let due = match self.unlocked.last_totp_request_at {
            Some(t) => t.elapsed() >= TOTP_REFRESH_INTERVAL,
            None => true,
        };
        if !due {
            return;
        }
        self.unlocked.last_totp_request_at = Some(Instant::now());
        let _ = self.cmd_tx.send(Command::GetTotp { id });
    }

    fn cmd_tx(&self) -> &mpsc::Sender<Command> {
        &self.cmd_tx
    }
}

impl eframe::App for VaulticGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_dirty {
            ctx.style_mut(|style| {
                self.theme.apply(&mut style.visuals);
            });
            self.theme_dirty = false;
        }

        self.drain_events();
        self.pump_search_debounce();
        self.pump_toast();
        self.pump_totp();

        // Repaint cadence: enough for the timer/toast tickers and live
        // status updates without spinning.
        ctx.request_repaint_after(Duration::from_millis(500));

        screens::draw_header(ctx, self);
        screens::draw_footer(ctx, &self.socket_path_label, &self.theme);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(theme::SPACE_MD);
            screens::draw_central(ui, ctx, self);
        });
    }
}

/// Default vault path matches the CLI: `~/.vaultic`.
fn default_vault_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".vaultic")
    } else {
        PathBuf::from(".vaultic")
    }
}
