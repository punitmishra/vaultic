//! Drawing routines for VaulticGui's various states.
//!
//! Kept separate from `mod.rs` so the state machine and event handling read
//! independently from the visual code.

use std::path::PathBuf;
use std::time::Instant;

use eframe::egui;
use uuid::Uuid;

use crate::gui::worker::Command;
use crate::gui::{AgentView, Toast, VaulticGui};

/// Top header panel: title, version, refresh button.
pub(crate) fn draw_header(ctx: &egui::Context, app: &mut VaulticGui) {
    egui::TopBottomPanel::top("vaultic-header").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading("Vaultic");
            ui.label(egui::RichText::new(env!("CARGO_PKG_VERSION")).weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    let _ = app.cmd_tx().send(Command::RefreshStatus);
                }
            });
        });
    });
}

/// Bottom footer: agent socket location.
pub(crate) fn draw_footer(ctx: &egui::Context, socket_path_label: &str) {
    egui::TopBottomPanel::bottom("vaultic-footer").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("agent socket: ").weak());
            ui.label(egui::RichText::new(socket_path_label).monospace().weak());
        });
    });
}

/// Decide which screen to render based on AgentView + unlocked status.
pub(crate) fn draw_central(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut VaulticGui) {
    match &app.agent {
        AgentView::Connecting => draw_connecting(ui),
        AgentView::Offline {
            reason,
            last_attempt,
        } => {
            // Clone the bits we need so we can drop the borrow before
            // calling helpers that take &mut app.
            let reason = reason.clone();
            let elapsed = last_attempt.elapsed();
            draw_offline(ui, &reason, elapsed.as_secs());
        }
        AgentView::Online { status, pong, .. } => {
            if status.unlocked {
                let entry_count = status.entry_count.unwrap_or(0);
                let vault_path_label = status.vault_path.clone().unwrap_or_default();
                let agent_version = pong.agent_version.clone();
                let protocol_version = pong.protocol_version;
                draw_unlocked(
                    ui,
                    ctx,
                    app,
                    entry_count,
                    vault_path_label,
                    agent_version,
                    protocol_version,
                );
            } else {
                draw_unlock_form(ui, app);
            }
        }
    }
}

// ============ Connecting ============

fn draw_connecting(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label("Connecting to vaultic-agent…");
    });
}

// ============ Offline ============

fn draw_offline(ui: &mut egui::Ui, reason: &str, elapsed_secs: u64) {
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
    ui.label(egui::RichText::new(format!("last attempt: {}s ago", elapsed_secs)).weak());
}

// ============ Unlock form ============

fn draw_unlock_form(ui: &mut egui::Ui, app: &mut VaulticGui) {
    ui.colored_label(egui::Color32::from_rgb(0xCC, 0xAA, 0x55), "Vault locked");
    ui.add_space(12.0);

    ui.label("Vault path:");
    ui.add(
        egui::TextEdit::singleline(&mut app.unlock.vault_path)
            .desired_width(420.0)
            .hint_text("~/.vaultic"),
    );

    ui.add_space(8.0);
    ui.label("Master password:");
    let password_widget = egui::TextEdit::singleline(&mut app.unlock.password)
        .desired_width(420.0)
        .password(true);
    let response = ui.add(password_widget);

    // Submit on Enter inside the password field.
    let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

    ui.add_space(8.0);

    let can_submit = !app.unlock.submitting
        && !app.unlock.password.is_empty()
        && !app.unlock.vault_path.trim().is_empty();

    let unlock_clicked = ui
        .add_enabled(
            can_submit,
            egui::Button::new(if app.unlock.submitting {
                "Unlocking…"
            } else {
                "Unlock"
            }),
        )
        .clicked();

    if (unlock_clicked || enter_pressed) && can_submit {
        let path = PathBuf::from(app.unlock.vault_path.trim());
        let password = std::mem::take(&mut app.unlock.password);
        app.unlock.submitting = true;
        app.unlock.error = None;
        let _ = app.cmd_tx().send(Command::Unlock {
            vault_path: path,
            password,
        });
    }

    if let Some(err) = &app.unlock.error {
        ui.add_space(8.0);
        ui.colored_label(egui::Color32::from_rgb(0xCC, 0x55, 0x55), err.as_str());
    }
}

// ============ Unlocked: list + detail split ============

fn draw_unlocked(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    app: &mut VaulticGui,
    entry_count: usize,
    vault_path_label: String,
    agent_version: String,
    protocol_version: u32,
) {
    // Top metadata row.
    ui.horizontal(|ui| {
        ui.colored_label(egui::Color32::from_rgb(0x55, 0xCC, 0x77), "Vault unlocked");
        ui.label(format!("· {} entries", entry_count));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Lock").clicked() {
                let _ = app.cmd_tx().send(Command::Lock);
            }
        });
    });
    if !vault_path_label.is_empty() {
        ui.label(egui::RichText::new(&vault_path_label).monospace().weak());
    }

    ui.add_space(8.0);
    ui.separator();

    // Two-column split: list on the left, detail on the right.
    ui.columns(2, |cols| {
        cols[0].set_min_width(220.0);
        draw_list_pane(&mut cols[0], app);
        draw_detail_pane(&mut cols[1], ctx, app);
    });

    ui.add_space(8.0);
    ui.separator();
    ui.label(
        egui::RichText::new(format!(
            "agent v{}, protocol v{}",
            agent_version, protocol_version
        ))
        .weak(),
    );

    // Toast last so it floats over the rest.
    if let Some(t) = &app.unlocked.toast {
        draw_toast(ctx, t);
    }
}

fn draw_list_pane(ui: &mut egui::Ui, app: &mut VaulticGui) {
    // Search box.
    let search_response = ui.add(
        egui::TextEdit::singleline(&mut app.unlocked.search_query)
            .desired_width(f32::INFINITY)
            .hint_text("Search…"),
    );
    if search_response.changed() {
        app.unlocked.search_pending_since = Some(Instant::now());
    }

    ui.add_space(6.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if app.unlocked.entries.is_empty() {
                ui.label(egui::RichText::new("No entries match.").italics().weak());
                return;
            }
            // Clone the entry list locally for iteration so we can
            // mutate selection state inside the loop.
            let entries = app.unlocked.entries.clone();
            let mut newly_selected: Option<Uuid> = None;
            for entry in &entries {
                let selected = app.unlocked.selected_id == Some(entry.id);
                let label = entry.name.as_str();
                let response = ui.selectable_label(selected, label);
                if response.clicked() {
                    newly_selected = Some(entry.id);
                }
                if let Some(uname) = entry.username.as_deref() {
                    if !uname.is_empty() {
                        ui.label(egui::RichText::new(uname).small().weak());
                    }
                }
                ui.add_space(2.0);
            }
            if let Some(id) = newly_selected {
                if app.unlocked.selected_id != Some(id) {
                    app.unlocked.selected_id = Some(id);
                    app.unlocked.detail = None;
                    app.unlocked.password_revealed = false;
                    let _ = app.cmd_tx().send(Command::LoadEntry { id });
                }
            }
        });
}

fn draw_detail_pane(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut VaulticGui) {
    let Some(selected_id) = app.unlocked.selected_id else {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Select an entry to see details.")
                .italics()
                .weak(),
        );
        return;
    };

    let detail = match &app.unlocked.detail {
        Some(d) => d.clone(),
        None => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading entry…");
            });
            // Defensive: if detail.None and selected_id matches, kick off
            // a fetch in case we missed the event somehow.
            let _ = app.cmd_tx().send(Command::LoadEntry { id: selected_id });
            return;
        }
    };

    ui.heading(&detail.name);
    if detail.favorite {
        ui.label(egui::RichText::new("★ favorite").weak());
    }

    ui.add_space(6.0);

    if let Some(username) = &detail.username {
        labeled_value(ui, "Username", username);
        if ui.small_button("Copy username").clicked() {
            copy_to_clipboard(app, username, "Username copied");
        }
        ui.add_space(4.0);
    }

    if let Some(password) = &detail.password {
        ui.horizontal(|ui| {
            ui.label("Password:");
            if app.unlocked.password_revealed {
                ui.label(egui::RichText::new(password.expose()).monospace());
            } else {
                ui.label(egui::RichText::new("••••••••••••").monospace().weak());
            }
        });
        ui.horizontal(|ui| {
            if ui
                .small_button(if app.unlocked.password_revealed {
                    "Hide"
                } else {
                    "Reveal"
                })
                .clicked()
            {
                app.unlocked.password_revealed = !app.unlocked.password_revealed;
            }
            if ui.small_button("Copy password").clicked() {
                let value = password.expose().to_string();
                copy_to_clipboard(app, &value, "Password copied");
            }
        });
        ui.add_space(4.0);
    }

    if let Some(url) = &detail.url {
        labeled_value(ui, "URL", url);
        ui.add_space(4.0);
    }

    if !detail.tags.is_empty() {
        labeled_value(ui, "Tags", &detail.tags.join(", "));
        ui.add_space(4.0);
    }

    if let Some(folder) = &detail.folder {
        labeled_value(ui, "Folder", folder);
        ui.add_space(4.0);
    }

    if let Some(notes) = &detail.notes {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Notes").weak());
        ui.add(
            egui::TextEdit::multiline(&mut notes.expose().to_string())
                .desired_width(f32::INFINITY)
                .desired_rows(3)
                .interactive(false),
        );
    }

    // Force a repaint while detail is shown so toast timing stays smooth.
    let _ = ctx;
}

fn labeled_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).weak());
        ui.label(value);
    });
}

fn copy_to_clipboard(app: &mut VaulticGui, value: &str, toast_message: &str) {
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(value.to_string())) {
        Ok(()) => {
            app.unlocked.toast = Some(Toast {
                message: toast_message.to_string(),
                shown_at: Instant::now(),
            });
        }
        Err(e) => {
            app.unlocked.toast = Some(Toast {
                message: format!("Clipboard error: {}", e),
                shown_at: Instant::now(),
            });
        }
    }
}

fn draw_toast(ctx: &egui::Context, toast: &Toast) {
    egui::Area::new(egui::Id::new("vaultic-toast"))
        .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -32.0])
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style()).show(ui, |ui| {
                ui.label(&toast.message);
            });
        });
}
