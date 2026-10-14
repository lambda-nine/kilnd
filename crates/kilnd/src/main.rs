use std::ffi::CString;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use kilnd::manager::{Limits, Manager};
use kilnd::runtime::kiln::KilnRuntime;
use kilnd::store::Store;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Control daemon for kiln sandboxes: gRPC over a Unix socket, state in SQLite.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// API socket.
    #[arg(long, default_value = "/run/kilnd/kilnd.sock")]
    socket: PathBuf,
    /// Group allowed to use the socket. Empty means root only.
    #[arg(long, default_value = "kilnd")]
    socket_group: String,
    /// Directory for the SQLite database (created 0700).
    #[arg(long, default_value = "/var/lib/kilnd")]
    state_dir: PathBuf,
    /// The kiln binary (absolute path).
    #[arg(long, default_value = "/usr/local/bin/kiln")]
    kiln: PathBuf,
    /// Execution timeout when a request gives none, in seconds.
    #[arg(long, default_value_t = 60)]
    default_timeout_secs: u64,
    /// Longest execution timeout a request may ask for, in seconds.
    #[arg(long, default_value_t = 3600)]
    max_timeout_secs: u64,
    /// Bytes of stdout and of stderr kept per execution.
    #[arg(long, default_value_t = 1 << 20)]
    max_output_bytes: usize,
    /// Sandboxes that may exist at once.
    #[arg(long, default_value_t = 32)]
    max_sandboxes: u32,
    /// On SIGTERM, how long running requests may finish before executions are
    /// canceled, in seconds.
    #[arg(long, default_value_t = 30)]
    shutdown_grace_secs: u64,
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let filter = EnvFilter::try_from_env("KILND_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Colors only on a terminal; journald and files get plain text.
    let logs = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());
    match args.log_format {
        LogFormat::Text => logs.init(),
        LogFormat::Json => logs.json().flatten_event(true).init(),
    }
    // Everything kilnd creates is private unless it widens it on purpose.
    // SAFETY: umask has no preconditions.
    unsafe { libc::umask(0o077) };

    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "start async runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %format!("{e:#}"), "kilnd failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("kilnd must run as root: kiln needs root to create sandboxes");
    }
    if !args.kiln.is_absolute() || !args.kiln.is_file() {
        bail!("--kiln must be an absolute path to the kiln binary, got {}", args.kiln.display());
    }
    let gid = match args.socket_group.as_str() {
        "" => None,
        name => Some(group_id(name)?),
    };
    let limits = Limits {
        default_timeout: Duration::from_secs(args.default_timeout_secs),
        max_timeout: Duration::from_secs(args.max_timeout_secs),
        max_output_bytes: args.max_output_bytes,
        max_sandboxes: args.max_sandboxes,
        ..Limits::default()
    };
    if limits.default_timeout > limits.max_timeout {
        bail!("--default-timeout-secs is above --max-timeout-secs");
    }

    let store = Store::open(&args.state_dir)?;
    let manager = Arc::new(Manager::new(KilnRuntime::new(args.kiln.clone()), store, limits));
    let r = manager.reconcile().await.context("startup reconciliation")?;
    info!(
        gc_removed = r.gc_removed.len(),
        lost = r.lost.len(),
        failed = r.failed.len(),
        deleted = r.deleted.len(),
        still_deleting = r.still_deleting.len(),
        interrupted_executions = r.interrupted_executions,
        unmanaged = r.unmanaged.len(),
        "reconciled with kiln"
    );

    let listener = kilnd::server::bind(&args.socket, gid)?;
    info!(socket = %args.socket.display(), group = %args.socket_group, version = env!("CARGO_PKG_VERSION"), "serving");
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => info!("SIGTERM"),
            _ = int.recv() => info!("SIGINT"),
        }
    };
    let result = kilnd::server::serve(manager, listener, shutdown, Duration::from_secs(args.shutdown_grace_secs)).await;
    let _ = std::fs::remove_file(&args.socket);
    info!("stopped");
    result
}

fn group_id(name: &str) -> Result<u32> {
    let cname = CString::new(name).context("group name contains NUL")?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe { libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 {
        bail!("look up group {name:?}: {}", std::io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        bail!("group {name:?} does not exist; create it (groupadd --system {name}) or pass --socket-group ''");
    }
    Ok(grp.gr_gid)
}
