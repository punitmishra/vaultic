//! `vaultic-agent` — the long-running daemon that holds an unlocked vault key
//! in memory and serves clients over a Unix-domain socket.
//!
//! This binary is intentionally a stub right now: Session 1 of the work
//! tracked in https://github.com/punitmishra/vaultic/issues/9 lands the
//! protocol types and the binary entry, with no actual socket-listener logic.
//! Session 2 implements unlock/lock/status/list/get/totp methods and binds
//! the socket. The CLI surface here is forward-looking so users can `cargo
//! install` the agent today and have stable command names.

use std::process::ExitCode;

use clap::Parser;
use vaultic::agent::{paths, protocol::PROTOCOL_VERSION};

#[derive(Debug, Parser)]
#[command(
    name = "vaultic-agent",
    version,
    about = "Background agent for the Vaultic password manager",
    long_about = "Holds an unlocked vault key in memory and serves clients (GUI, CLI, future browser extension) over a Unix-domain socket.\n\nSession 1 stub: prints status only; the listener implementation lands in a follow-up PR."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Start the daemon. (Stub: not yet implemented.)
    Start,
    /// Stop a running daemon. (Stub: not yet implemented.)
    Stop,
    /// Print the resolved socket path and protocol version.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Status => match paths::agent_socket_path() {
            Ok(p) => {
                println!("vaultic-agent");
                println!("  protocol_version: {}", PROTOCOL_VERSION);
                println!("  socket_path:      {}", p.display());
                println!("  state:            not_running (Session 1 stub)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error resolving socket path: {}", e);
                ExitCode::from(2)
            }
        },
        Command::Start | Command::Stop => {
            eprintln!(
                "vaultic-agent: not yet implemented (Session 1 stub).\n\
                 The listener and lifecycle commands ship in the next PR;\n\
                 see https://github.com/punitmishra/vaultic/issues/9"
            );
            ExitCode::from(64)
        }
    }
}
