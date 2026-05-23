//! `vaultic-gui` — egui-based desktop client for vaultic.
//!
//! Connects to a running `vaultic-agent` over its Unix socket. Session 3 of
//! the work tracked in https://github.com/punitmishra/vaultic/issues/9 ships
//! the connection-status shell; later sessions add unlock / list / detail.

use std::path::PathBuf;
use std::sync::mpsc;

use clap::Parser;
use vaultic::agent::paths;
use vaultic::gui::worker;

#[derive(Debug, Parser)]
#[command(
    name = "vaultic-gui",
    version,
    about = "Desktop GUI for the Vaultic password manager",
    long_about = "Connects to a running vaultic-agent over its Unix socket and shows vault state.\n\nSession 3 of #9 ships the connection-status shell. Unlock + entry list + TOTP arrive in follow-up sessions."
)]
struct Cli {
    /// Override the agent socket path (defaults to the per-OS location).
    #[arg(long)]
    socket: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let socket_path = match cli.socket {
        Some(p) => p,
        None => paths::agent_socket_path()?,
    };

    // Tokio runs on a worker thread; eframe owns the main thread because
    // macOS AppKit insists.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<worker::Command>();
    let (event_tx, event_rx) = mpsc::channel::<worker::Event>();

    let socket_label = socket_path.display().to_string();
    let app_factory_socket = socket_path.clone();
    let runtime_for_factory = std::sync::Arc::new(runtime);
    let runtime_for_drop = runtime_for_factory.clone();

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([520.0, 380.0])
            .with_min_inner_size([420.0, 280.0])
            .with_title("Vaultic"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Vaultic",
        native_options,
        Box::new(move |cc| {
            // Spawn the worker now — we have an egui::Context.
            worker::spawn(
                &runtime_for_factory,
                app_factory_socket.clone(),
                cc.egui_ctx.clone(),
                cmd_rx,
                event_tx.clone(),
            );
            Ok(Box::new(vaultic::gui::VaulticGui::new(
                cmd_tx.clone(),
                event_rx,
                socket_label.clone(),
            )))
        }),
    );

    // Tear down the runtime when eframe returns. Letting it Drop without
    // shutting down would leak workers.
    if let Ok(rt) = std::sync::Arc::try_unwrap(runtime_for_drop) {
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
    }

    result.map_err(|e| -> Box<dyn std::error::Error> {
        Box::new(std::io::Error::other(e.to_string()))
    })
}
