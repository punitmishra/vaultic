//! `vaultic-agent` — long-running daemon that holds an unlocked vault key in
//! memory and serves clients over a Unix-domain socket.
//!
//! See `docs/AGENT_PROTOCOL.md` for the wire protocol.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tokio::sync::mpsc;
use uuid::Uuid;
use vaultic::agent::{
    paths,
    protocol::{
        read_frame_async, write_frame_async, Frame, Method, Request, Response, ResponseBody,
        PROTOCOL_VERSION,
    },
    serve, ServerConfig,
};

#[derive(Debug, Parser)]
#[command(
    name = "vaultic-agent",
    version,
    about = "Background agent for the Vaultic password manager",
    long_about = "Holds an unlocked vault key in memory and serves clients (GUI, CLI, future browser extension) over a Unix-domain socket."
)]
struct Cli {
    /// Override the socket path (defaults to the per-OS location).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Start the daemon. Runs in the foreground until SIGINT or `stop`.
    Start,
    /// Send a graceful shutdown to a running daemon.
    Stop,
    /// Show whether a daemon is running and where its socket lives.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vaultic-agent: failed to start tokio runtime: {}", e);
            return ExitCode::from(70);
        }
    };
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let socket_path = match resolve_socket(cli.socket.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vaultic-agent: {}", e);
            return ExitCode::from(2);
        }
    };

    match cli.command {
        Command::Status => status(&socket_path).await,
        Command::Start => start(socket_path).await,
        Command::Stop => stop(&socket_path).await,
    }
}

fn resolve_socket(override_path: Option<PathBuf>) -> Result<PathBuf, paths::PathError> {
    match override_path {
        Some(p) => Ok(p),
        None => paths::agent_socket_path(),
    }
}

async fn status(socket_path: &std::path::Path) -> ExitCode {
    println!("vaultic-agent");
    println!("  protocol_version: {}", PROTOCOL_VERSION);
    println!("  socket_path:      {}", socket_path.display());
    match probe(socket_path).await {
        Ok(true) => {
            println!("  state:            running");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("  state:            not_running");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("  state:            error ({})", e);
            ExitCode::from(1)
        }
    }
}

/// Try to ping the daemon. Returns `Ok(true)` if a daemon answers, `Ok(false)`
/// if the socket file isn't present or the connection is refused (no listener).
async fn probe(socket_path: &std::path::Path) -> std::io::Result<bool> {
    if !socket_path.exists() {
        return Ok(false);
    }
    let mut stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(false),
        Err(e) => return Err(e),
    };

    let req = Frame::Request(Request {
        id: Uuid::new_v4(),
        method: Method::Ping,
    });
    write_frame_async(&mut stream, &req)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let resp = read_frame_async(&mut stream)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(matches!(
        resp,
        Some(Frame::Response(Response {
            body: ResponseBody::Result(_),
            ..
        }))
    ))
}

async fn start(socket_path: PathBuf) -> ExitCode {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Wire SIGINT (Ctrl+C) to graceful shutdown.
    let shutdown_for_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_for_signal.send(()).await;
        }
    });

    let config = ServerConfig {
        socket_path: socket_path.clone(),
        inactivity_timeout: vaultic::agent::state::DEFAULT_INACTIVITY_TIMEOUT,
    };

    println!("vaultic-agent listening on {}", socket_path.display());
    match serve(config, shutdown_rx).await {
        Ok(()) => {
            println!("vaultic-agent: stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("vaultic-agent: {}", e);
            ExitCode::from(1)
        }
    }
}

async fn stop(socket_path: &std::path::Path) -> ExitCode {
    let mut stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "vaultic-agent: not running (no socket at {})",
                socket_path.display()
            );
            return ExitCode::from(1);
        }
    };

    let req = Frame::Request(Request {
        id: Uuid::new_v4(),
        method: Method::Shutdown,
    });
    if let Err(e) = write_frame_async(&mut stream, &req).await {
        eprintln!("vaultic-agent: send failed: {}", e);
        return ExitCode::from(1);
    }

    // Read the response (we don't strictly need it, but it confirms the
    // daemon accepted the shutdown).
    match read_frame_async(&mut stream).await {
        Ok(Some(Frame::Response(_))) => {
            println!("vaultic-agent: shutdown sent");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("vaultic-agent: unexpected response");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("vaultic-agent: read failed: {}", e);
            ExitCode::from(1)
        }
    }
}
