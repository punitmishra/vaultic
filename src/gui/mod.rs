//! `vaultic-gui` — egui-based desktop app that talks to `vaultic-agent`.
//!
//! Session 3 of #9 ships the connection-status shell. Sessions 4 and 5 add
//! unlock / list / detail / TOTP screens on top.
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
//!     │            │◄───────────┤ - reconnect      │
//!     └────────────┘  Event     └──────────────────┘
//! ```
//!
//! `Command` is what the GUI asks the worker to do. `Event` is what the
//! worker reports back. The worker also pushes `RepaintRequest` to egui via
//! its `egui::Context` so we don't have to poll on the UI thread.

pub mod worker;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::agent::protocol::{PongView, StatusView};
use crate::gui::worker::{Command, Event};

/// One-shot status the agent showed us (or the reason we couldn't get one).
#[derive(Debug, Clone, Default)]
enum AgentView {
    /// Initial state. Worker is trying its first connect.
    #[default]
    Connecting,
    /// Daemon connected at least once and answered `ping`/`status`.
    Online {
        pong: PongView,
        status: StatusView,
        last_refresh: Instant,
    },
    /// Last connect attempt couldn't reach the socket.
    Offline {
        reason: String,
        last_attempt: Instant,
    },
}

/// `eframe::App` implementation. Owns the channel ends to the tokio worker
/// and a small bag of cached state.
pub struct VaulticGui {
    cmd_tx: mpsc::Sender<Command>,
    event_rx: mpsc::Receiver<Event>,
    agent: AgentView,
    /// Set true when the user clicks "Unlock"; cleared when they dismiss.
    show_unlock_stub: bool,
    socket_path_label: String,
}

impl VaulticGui {
    /// Build the app. Caller is responsible for spawning the worker that
    /// owns the receiving end of `cmd_tx` and the sending end of `event_rx`.
    pub fn new(
        cmd_tx: mpsc::Sender<Command>,
        event_rx: mpsc::Receiver<Event>,
        socket_path_label: String,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx,
            agent: AgentView::Connecting,
            show_unlock_stub: false,
            socket_path_label,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                Event::Pong { pong, status } => {
                    self.agent = AgentView::Online {
                        pong,
                        status,
                        last_refresh: Instant::now(),
                    };
                }
                Event::Offline { reason } => {
                    self.agent = AgentView::Offline {
                        reason,
                        last_attempt: Instant::now(),
                    };
                }
            }
        }
    }
}

impl eframe::App for VaulticGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        // Ask the worker to refresh on a cadence. The worker also requests
        // a repaint on each event so we don't spin.
        ctx.request_repaint_after(Duration::from_secs(5));

        egui::TopBottomPanel::top("vaultic-header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Vaultic");
                ui.label(egui::RichText::new(env!("CARGO_PKG_VERSION")).weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh").clicked() {
                        let _ = self.cmd_tx.send(Command::RefreshStatus);
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("vaultic-footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("agent socket: ").weak());
                ui.label(
                    egui::RichText::new(&self.socket_path_label)
                        .monospace()
                        .weak(),
                );
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            self.draw_agent_view(ui);

            if self.show_unlock_stub {
                self.draw_unlock_stub(ctx);
            }
        });
    }
}

impl VaulticGui {
    fn draw_agent_view(&mut self, ui: &mut egui::Ui) {
        match &self.agent {
            AgentView::Connecting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting to vaultic-agent…");
                });
            }
            AgentView::Offline {
                reason,
                last_attempt,
            } => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xCC, 0x55, 0x55),
                    "Agent not running",
                );
                ui.add_space(4.0);
                ui.label(egui::RichText::new(reason).monospace().weak());
                ui.add_space(8.0);
                ui.label("Start the daemon in a terminal:");
                ui.code("vaultic-agent start");
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!(
                        "last attempt: {}s ago",
                        last_attempt.elapsed().as_secs()
                    ))
                    .weak(),
                );
            }
            AgentView::Online {
                pong,
                status,
                last_refresh,
            } => {
                if status.unlocked {
                    ui.colored_label(egui::Color32::from_rgb(0x55, 0xCC, 0x77), "Vault unlocked");
                    ui.add_space(4.0);
                    if let Some(path) = &status.vault_path {
                        ui.label(egui::RichText::new(path).monospace());
                    }
                    if let Some(n) = status.entry_count {
                        ui.label(format!("{} entries", n));
                    }
                    ui.add_space(8.0);
                    if ui.button("Lock").clicked() {
                        let _ = self.cmd_tx.send(Command::Lock);
                    }
                } else {
                    ui.colored_label(egui::Color32::from_rgb(0xCC, 0xAA, 0x55), "Vault locked");
                    ui.add_space(8.0);
                    if ui.button("Unlock…").clicked() {
                        self.show_unlock_stub = true;
                    }
                }

                ui.add_space(12.0);
                ui.separator();
                ui.label(
                    egui::RichText::new(format!(
                        "agent v{}, protocol v{}, refreshed {}s ago",
                        pong.agent_version,
                        pong.protocol_version,
                        last_refresh.elapsed().as_secs()
                    ))
                    .weak(),
                );
            }
        }
    }

    fn draw_unlock_stub(&mut self, ctx: &egui::Context) {
        egui::Window::new("Unlock")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(
                    "Password input + KDF + agent unlock arrives in Session 4 \
                     of issue #9.",
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("For now you can unlock from the CLI: vaultic unlock")
                        .weak(),
                );
                ui.add_space(8.0);
                if ui.button("OK").clicked() {
                    self.show_unlock_stub = false;
                }
            });
    }
}
