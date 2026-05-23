//! Drawing routines for VaulticGui's various states.
//!
//! Kept separate from `mod.rs` so the state machine and event handling read
//! independently from the visual code.

use std::path::PathBuf;
use std::time::Instant;

use eframe::egui;
use uuid::Uuid;

use crate::gui::theme::{Theme, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL, SPACE_XS, THEME_NAMES};
use crate::gui::worker::Command;
use crate::gui::{AgentView, Toast, VaulticGui, COPY_TOAST_SUFFIX};

/// Top header panel: title, version, theme picker, refresh button.
pub(crate) fn draw_header(ctx: &egui::Context, app: &mut VaulticGui) {
    egui::TopBottomPanel::top("vaultic-header")
        .show_separator_line(true)
        .show(ctx, |ui| {
            ui.add_space(SPACE_XS);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Vaultic")
                            .heading()
                            .color(app.theme().fg),
                    )
                    .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(env!("CARGO_PKG_VERSION"))
                            .small()
                            .color(app.theme().fg_muted),
                    )
                    .selectable(false),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Refresh").clicked() {
                        let _ = app.cmd_tx().send(Command::RefreshStatus);
                    }
                    ui.add_space(SPACE_SM);
                    draw_theme_picker(ui, app);
                });
            });
            ui.add_space(SPACE_XS);
        });
}

fn draw_theme_picker(ui: &mut egui::Ui, app: &mut VaulticGui) {
    // Find the current theme name by comparing background bytes — themes
    // are distinct by `bg`. Cheap, no need for an extra field on the app.
    let current = current_theme_name(app);
    let mut picked: Option<&'static str> = None;
    egui::ComboBox::from_id_salt("vaultic-theme-picker")
        .selected_text(current)
        .show_ui(ui, |ui| {
            for name in THEME_NAMES {
                if ui.selectable_label(*name == current, *name).clicked() {
                    picked = Some(*name);
                }
            }
        });
    if let Some(name) = picked {
        app.set_theme_by_name(name);
    }
}

fn current_theme_name(app: &VaulticGui) -> &'static str {
    let bg = app.theme().bg;
    for name in THEME_NAMES {
        if let Some(t) = Theme::from_name(name) {
            if t.bg == bg {
                return name;
            }
        }
    }
    "default"
}

/// Bottom footer: agent socket location.
pub(crate) fn draw_footer(ctx: &egui::Context, socket_path_label: &str, theme: &Theme) {
    egui::TopBottomPanel::bottom("vaultic-footer").show(ctx, |ui| {
        ui.add_space(SPACE_XS);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("agent socket: ").color(theme.fg_muted));
            ui.label(
                egui::RichText::new(socket_path_label)
                    .monospace()
                    .color(theme.fg_muted),
            );
        });
        ui.add_space(SPACE_XS);
    });
}

/// Decide which screen to render based on AgentView + unlocked status.
pub(crate) fn draw_central(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut VaulticGui) {
    match &app.agent {
        AgentView::Connecting => draw_connecting(ui, app.theme()),
        AgentView::Offline {
            reason,
            last_attempt,
        } => {
            let reason = reason.clone();
            let elapsed = last_attempt.elapsed();
            draw_offline(ui, app.theme(), &reason, elapsed.as_secs());
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

// ============ Reusable bits ============

/// Colored status dot followed by a label. Replaces ad-hoc "colored_label"
/// calls so all status indicators share the same shape.
fn status_row(ui: &mut egui::Ui, color: egui::Color32, fg: egui::Color32, label: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 4.0, color);
        ui.add_space(SPACE_SM);
        ui.label(egui::RichText::new(label).color(fg).strong());
    });
}

// ============ Connecting ============

fn draw_connecting(ui: &mut egui::Ui, theme: &Theme) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.add_space(SPACE_SM);
        ui.label(egui::RichText::new("Connecting to vaultic-agent…").color(theme.fg_muted));
    });
}

// ============ Offline ============

fn draw_offline(ui: &mut egui::Ui, theme: &Theme, reason: &str, elapsed_secs: u64) {
    status_row(ui, theme.error, theme.fg, "Agent not running");
    ui.add_space(SPACE_SM);
    ui.label(
        egui::RichText::new(reason)
            .monospace()
            .color(theme.fg_muted),
    );
    ui.add_space(SPACE_MD);
    ui.label("Start the daemon in a terminal:");
    ui.code("vaultic-agent start");
    ui.add_space(SPACE_MD);
    ui.label(
        egui::RichText::new(format!("last attempt: {}s ago", elapsed_secs))
            .small()
            .color(theme.fg_muted),
    );
}

// ============ Unlock form ============

fn draw_unlock_form(ui: &mut egui::Ui, app: &mut VaulticGui) {
    let theme = *app.theme();
    status_row(ui, theme.warning, theme.fg, "Vault locked");
    ui.add_space(SPACE_LG);

    ui.label(egui::RichText::new("Vault path").color(theme.fg_muted));
    ui.add(
        egui::TextEdit::singleline(&mut app.unlock.vault_path)
            .desired_width(420.0)
            .hint_text("~/.vaultic"),
    );

    ui.add_space(SPACE_MD);
    ui.label(egui::RichText::new("Master password").color(theme.fg_muted));
    let password_widget = egui::TextEdit::singleline(&mut app.unlock.password)
        .desired_width(420.0)
        .password(true);
    let response = ui.add(password_widget);

    let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

    ui.add_space(SPACE_MD);

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
        ui.add_space(SPACE_MD);
        ui.colored_label(theme.error, err.as_str());
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
    let theme = *app.theme();

    // Top metadata row.
    ui.horizontal(|ui| {
        status_row(ui, theme.success, theme.fg, "Vault unlocked");
        ui.label(egui::RichText::new(format!("· {} entries", entry_count)).color(theme.fg_muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Lock").clicked() {
                let _ = app.cmd_tx().send(Command::Lock);
            }
        });
    });
    if !vault_path_label.is_empty() {
        ui.label(
            egui::RichText::new(&vault_path_label)
                .monospace()
                .small()
                .color(theme.fg_muted),
        );
    }

    ui.add_space(SPACE_MD);
    ui.separator();

    // Apply keyboard navigation BEFORE drawing the list so the visible
    // selection follows the key press in the same frame.
    apply_keyboard_navigation(ctx, app);

    ui.columns(2, |cols| {
        cols[0].set_min_width(220.0);
        draw_list_pane(&mut cols[0], app, &theme);
        draw_detail_pane(&mut cols[1], ctx, app, &theme);
    });

    ui.add_space(SPACE_MD);
    ui.separator();
    ui.label(
        egui::RichText::new(format!(
            "agent v{}, protocol v{}",
            agent_version, protocol_version
        ))
        .small()
        .color(theme.fg_muted),
    );

    if let Some(t) = &app.unlocked.toast {
        draw_toast(ctx, &theme, t);
    }
}

/// Process arrow keys / j / k / `/` from anywhere in the unlocked view.
/// Bindings are deliberately small:
///   - j or ArrowDown: next entry
///   - k or ArrowUp: previous entry
///   - /: focus the search box on the next frame
///   - Esc: clear current search if non-empty; otherwise leave selection
fn apply_keyboard_navigation(ctx: &egui::Context, app: &mut VaulticGui) {
    if ctx.wants_keyboard_input() {
        // A text field has focus — let it handle the keys.
        return;
    }

    let move_delta = ctx.input(|i| {
        if i.key_pressed(egui::Key::ArrowDown) || i.key_pressed(egui::Key::J) {
            1
        } else if i.key_pressed(egui::Key::ArrowUp) || i.key_pressed(egui::Key::K) {
            -1
        } else {
            0
        }
    });
    if move_delta != 0 {
        move_selection(app, move_delta);
    }

    let focus_search = ctx.input(|i| i.key_pressed(egui::Key::Slash));
    if focus_search {
        app.unlocked.focus_search_next_frame = true;
    }

    let escape = ctx.input(|i| i.key_pressed(egui::Key::Escape));
    if escape && !app.unlocked.search_query.is_empty() {
        app.unlocked.search_query.clear();
        app.unlocked.search_pending_since = Some(Instant::now());
    }
}

fn move_selection(app: &mut VaulticGui, delta: i32) {
    if app.unlocked.entries.is_empty() {
        return;
    }
    let current = app
        .unlocked
        .selected_id
        .and_then(|id| app.unlocked.entries.iter().position(|e| e.id == id));
    let new_index = match current {
        Some(idx) => {
            let len = app.unlocked.entries.len() as i32;
            let next = (idx as i32 + delta).rem_euclid(len);
            next as usize
        }
        None => {
            if delta > 0 {
                0
            } else {
                app.unlocked.entries.len() - 1
            }
        }
    };
    let id = app.unlocked.entries[new_index].id;
    if app.unlocked.selected_id != Some(id) {
        app.unlocked.selected_id = Some(id);
        app.unlocked.detail = None;
        app.unlocked.password_revealed = false;
        app.unlocked.totp = None;
        app.unlocked.last_totp_request_at = None;
        let _ = app.cmd_tx().send(Command::LoadEntry { id });
    }
}

fn draw_list_pane(ui: &mut egui::Ui, app: &mut VaulticGui, theme: &Theme) {
    let search_response = ui.add(
        egui::TextEdit::singleline(&mut app.unlocked.search_query)
            .desired_width(f32::INFINITY)
            .hint_text("Search…  (press / to focus)"),
    );
    if app.unlocked.focus_search_next_frame {
        search_response.request_focus();
        app.unlocked.focus_search_next_frame = false;
    }
    if search_response.changed() {
        app.unlocked.search_pending_since = Some(Instant::now());
    }

    ui.add_space(SPACE_SM);

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if app.unlocked.entries.is_empty() {
                ui.label(
                    egui::RichText::new("No entries match.")
                        .italics()
                        .color(theme.fg_muted),
                );
                return;
            }
            let entries = app.unlocked.entries.clone();
            let mut newly_selected: Option<Uuid> = None;
            for entry in &entries {
                let selected = app.unlocked.selected_id == Some(entry.id);
                let response = ui.selectable_label(selected, &entry.name);
                if response.clicked() {
                    newly_selected = Some(entry.id);
                }
                if let Some(uname) = entry.username.as_deref() {
                    if !uname.is_empty() {
                        ui.label(egui::RichText::new(uname).small().color(theme.fg_muted));
                    }
                }
                if entry.has_totp {
                    ui.label(egui::RichText::new("TOTP").small().color(theme.accent));
                }
                ui.add_space(SPACE_XS);
            }
            if let Some(id) = newly_selected {
                if app.unlocked.selected_id != Some(id) {
                    app.unlocked.selected_id = Some(id);
                    app.unlocked.detail = None;
                    app.unlocked.password_revealed = false;
                    app.unlocked.totp = None;
                    app.unlocked.last_totp_request_at = None;
                    let _ = app.cmd_tx().send(Command::LoadEntry { id });
                }
            }
        });
}

fn draw_detail_pane(ui: &mut egui::Ui, _ctx: &egui::Context, app: &mut VaulticGui, theme: &Theme) {
    let Some(selected_id) = app.unlocked.selected_id else {
        ui.add_space(SPACE_MD);
        ui.label(
            egui::RichText::new("Select an entry to see details.")
                .italics()
                .color(theme.fg_muted),
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
            let _ = app.cmd_tx().send(Command::LoadEntry { id: selected_id });
            return;
        }
    };

    ui.add(
        egui::Label::new(egui::RichText::new(&detail.name).heading().color(theme.fg))
            .selectable(false),
    );
    if detail.favorite {
        ui.label(
            egui::RichText::new("★ favorite")
                .small()
                .color(theme.warning),
        );
    }

    ui.add_space(SPACE_SM);

    if let Some(username) = &detail.username {
        labeled_value(ui, theme, "Username", username);
        if ui.small_button("Copy username").clicked() {
            let value = username.clone();
            copy_with_clear(app, &value, "Username copied");
        }
        ui.add_space(SPACE_SM);
    }

    if let Some(password) = &detail.password {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Password:").color(theme.fg_muted));
            if app.unlocked.password_revealed {
                ui.label(
                    egui::RichText::new(password.expose())
                        .monospace()
                        .color(theme.fg),
                );
            } else {
                ui.label(
                    egui::RichText::new("••••••••••••")
                        .monospace()
                        .color(theme.fg_muted),
                );
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
                copy_with_clear(app, &value, "Password copied");
            }
        });
        ui.add_space(SPACE_SM);
    }

    // TOTP block: only when the entry has a totp_secret. The actual code
    // comes from the agent via Method::GetTotp; we render whatever the
    // most recent reply was for this id.
    if detail.totp_secret.is_some() {
        draw_totp_block(ui, app, theme, selected_id);
        ui.add_space(SPACE_SM);
    }

    if let Some(url) = &detail.url {
        labeled_value(ui, theme, "URL", url);
        ui.add_space(SPACE_SM);
    }

    if !detail.tags.is_empty() {
        labeled_value(ui, theme, "Tags", &detail.tags.join(", "));
        ui.add_space(SPACE_SM);
    }

    if let Some(folder) = &detail.folder {
        labeled_value(ui, theme, "Folder", folder);
        ui.add_space(SPACE_SM);
    }

    if let Some(notes) = &detail.notes {
        ui.add_space(SPACE_MD);
        ui.label(egui::RichText::new("Notes").color(theme.fg_muted));
        ui.add(
            egui::TextEdit::multiline(&mut notes.expose().to_string())
                .desired_width(f32::INFINITY)
                .desired_rows(3)
                .interactive(false),
        );
    }
}

fn draw_totp_block(ui: &mut egui::Ui, app: &mut VaulticGui, theme: &Theme, selected_id: Uuid) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("TOTP:").color(theme.fg_muted));
        match &app.unlocked.totp {
            Some((id, view)) if *id == selected_id => {
                let formatted = if view.code.len() == 6 {
                    format!("{} {}", &view.code[..3], &view.code[3..])
                } else {
                    view.code.clone()
                };
                ui.label(
                    egui::RichText::new(&formatted)
                        .monospace()
                        .size(18.0)
                        .color(theme.accent),
                );
                ui.label(
                    egui::RichText::new(format!("{}s left", view.period_remaining_seconds))
                        .small()
                        .color(theme.fg_muted),
                );
            }
            _ => {
                ui.add(egui::Spinner::new());
            }
        }
    });

    // Progress bar for the current period.
    if let Some((id, view)) = &app.unlocked.totp {
        if *id == selected_id && view.period_total_seconds > 0 {
            let frac = view.period_remaining_seconds as f32 / view.period_total_seconds as f32;
            let bar = egui::ProgressBar::new(frac).desired_width(220.0);
            ui.add(bar);
        }
    }

    if let Some((id, view)) = &app.unlocked.totp {
        if *id == selected_id {
            let code = view.code.clone();
            if ui.small_button("Copy TOTP").clicked() {
                copy_with_clear(app, &code, "TOTP copied");
            }
        }
    }

    let _ = SPACE_XL; // reserved for future fine-tuning
}

fn labeled_value(ui: &mut egui::Ui, theme: &Theme, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).color(theme.fg_muted));
        ui.label(value);
    });
}

/// Set clipboard, schedule a 30s clear, surface a toast.
fn copy_with_clear(app: &mut VaulticGui, value: &str, base_message: &str) {
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(value.to_string())) {
        Ok(()) => {
            app.unlocked.toast = Some(Toast {
                message: format!("{}{}", base_message, COPY_TOAST_SUFFIX),
                shown_at: Instant::now(),
            });
            let _ = app.cmd_tx().send(Command::ClearClipboardIfMatches {
                sentinel: value.to_string(),
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

fn draw_toast(ctx: &egui::Context, theme: &Theme, toast: &Toast) {
    egui::Area::new(egui::Id::new("vaultic-toast"))
        .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -32.0])
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style())
                .fill(theme.bg_elevated)
                .stroke(theme.stroke)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&toast.message).color(theme.fg));
                });
        });
}
