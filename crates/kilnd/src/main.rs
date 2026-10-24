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
    /// Simultaneous admitted Unix connections; excess sockets are closed.
    #[arg(long, default_value_t = 64)]
    max_connections: usize,
    /// Simultaneous ordinary RPC handlers, after message decoding.
    #[arg(long, default_value_t = 64)]
    max_concurrent_rpcs: usize,
    /// Reserved simultaneous Health RPC handlers.
    #[arg(long, default_value_t = 4)]
    max_concurrent_health: usize,
    /// Global running and queued Exec admissions, including cleanup.
    #[arg(long, default_value_t = 32)]
    max_concurrent_execs: usize,
    /// Queued Exec requests per sandbox, in addition to one running request.
    #[arg(long, default_value_t = 8)]
    max_queued_execs_per_sandbox: usize,
    /// Aggregate stdin bytes retained by admitted Exec requests.
    #[arg(long, default_value_t = 16 << 20)]
    max_queued_exec_stdin_bytes: usize,
    /// HTTP/2 streams and concurrent requests per connection.
    #[arg(long, default_value_t = 8)]
    max_streams_per_connection: usize,
    /// Maximum decoded protobuf request size.
    #[arg(long, default_value_t = 2 << 20)]
    max_request_bytes: usize,
    /// Maximum encoded protobuf response size.
    #[arg(long, default_value_t = 4 << 20)]
    max_response_bytes: usize,
    /// Maximum number of sandboxes in one List page (at most 1000).
    #[arg(long, default_value_t = 200)]
    max_list_page_size: u32,
    /// Maximum encoded List response size.
    #[arg(long, default_value_t = 1 << 20)]
    max_list_response_bytes: usize,
    /// Shared backend Health probe timeout, in seconds.
    #[arg(long, default_value_t = 2)]
    health_probe_timeout_secs: u64,
    /// Cache lifetime of a successful Health probe, in seconds.
    #[arg(long, default_value_t = 5)]
    health_success_cache_secs: u64,
    /// Cache lifetime of a failed Health probe, in seconds.
    #[arg(long, default_value_t = 1)]
    health_failure_cache_secs: u64,
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

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
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
    let limits = validated_limits(&args)?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("kilnd must run as root: kiln needs root to create sandboxes");
    }
    if !args.kiln.is_absolute() || !args.kiln.is_file() {
        bail!(
            "--kiln must be an absolute path to the kiln binary, got {}",
            args.kiln.display()
        );
    }
    let gid = match args.socket_group.as_str() {
        "" => None,
        name => Some(group_id(name)?),
    };
    if args.socket.parent() == Some(args.state_dir.as_path()) {
        bail!(
            "--socket directory and --state-dir must be different so socket access cannot widen state permissions"
        );
    }

    // Store::open takes the state-directory lock before opening SQLite. Bind
    // then takes the socket-directory lock and reserves the endpoint. Both
    // ownership domains must be established before reconciliation mutates
    // durable state or invokes kiln.
    let store = Store::open(&args.state_dir)?;
    let socket = kilnd::server::bind(&args.socket, gid).await?;
    let manager = Arc::new(Manager::new(
        KilnRuntime::new(args.kiln.clone()),
        store,
        limits,
    ));
    let r = manager
        .reconcile()
        .await
        .context("startup reconciliation")?;
    info!(
        gc_removed = r.gc_removed.len(),
        recovered = r.recovered.len(),
        lost = r.lost.len(),
        failed = r.failed.len(),
        deleted = r.deleted.len(),
        still_deleting = r.still_deleting.len(),
        interrupted_executions = r.interrupted_executions,
        unmanaged = r.unmanaged.len(),
        "reconciled with kiln"
    );

    info!(socket = %args.socket.display(), group = %args.socket_group, version = env!("CARGO_PKG_VERSION"), "serving");
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => info!("SIGTERM"),
            _ = int.recv() => info!("SIGINT"),
        }
    };
    let result = kilnd::server::serve(
        manager,
        socket,
        shutdown,
        Duration::from_secs(args.shutdown_grace_secs),
    )
    .await;
    info!("stopped");
    result
}

fn validated_limits(args: &Args) -> Result<Limits> {
    let limits = Limits {
        default_timeout: Duration::from_secs(args.default_timeout_secs),
        max_timeout: Duration::from_secs(args.max_timeout_secs),
        max_output_bytes: args.max_output_bytes,
        max_sandboxes: args.max_sandboxes,
        max_connections: args.max_connections,
        max_concurrent_rpcs: args.max_concurrent_rpcs,
        max_concurrent_health: args.max_concurrent_health,
        max_concurrent_execs: args.max_concurrent_execs,
        max_queued_execs_per_sandbox: args.max_queued_execs_per_sandbox,
        max_queued_exec_stdin_bytes: args.max_queued_exec_stdin_bytes,
        max_streams_per_connection: args.max_streams_per_connection,
        max_request_bytes: args.max_request_bytes,
        max_response_bytes: args.max_response_bytes,
        max_list_page_size: args.max_list_page_size,
        max_list_response_bytes: args.max_list_response_bytes,
        health_probe_timeout: Duration::from_secs(args.health_probe_timeout_secs),
        health_success_cache: Duration::from_secs(args.health_success_cache_secs),
        health_failure_cache: Duration::from_secs(args.health_failure_cache_secs),
        ..Limits::default()
    };
    for (name, value) in [
        ("max-connections", limits.max_connections),
        ("max-concurrent-rpcs", limits.max_concurrent_rpcs),
        ("max-concurrent-health", limits.max_concurrent_health),
        ("max-concurrent-execs", limits.max_concurrent_execs),
        (
            "max-queued-exec-stdin-bytes",
            limits.max_queued_exec_stdin_bytes,
        ),
        (
            "max-streams-per-connection",
            limits.max_streams_per_connection,
        ),
    ] {
        if value == 0 {
            bail!("--{name} must be nonzero");
        }
        if u32::try_from(value).is_err() || value > tokio::sync::Semaphore::MAX_PERMITS {
            bail!("--{name} exceeds u32 semaphore capacity");
        }
    }
    let outstanding = limits
        .max_queued_execs_per_sandbox
        .checked_add(1)
        .context("--max-queued-execs-per-sandbox + 1 overflows")?;
    if u32::try_from(outstanding).is_err() || outstanding > tokio::sync::Semaphore::MAX_PERMITS {
        bail!("--max-queued-execs-per-sandbox + 1 exceeds u32 semaphore capacity");
    }
    for (name, value) in [
        ("max-output-bytes", limits.max_output_bytes),
        ("max-request-bytes", limits.max_request_bytes),
        ("max-response-bytes", limits.max_response_bytes),
        ("max-list-response-bytes", limits.max_list_response_bytes),
    ] {
        if value == 0 {
            bail!("--{name} must be nonzero");
        }
    }
    for (name, value) in [
        ("default-timeout-secs", args.default_timeout_secs),
        ("max-timeout-secs", args.max_timeout_secs),
        ("health-probe-timeout-secs", args.health_probe_timeout_secs),
        ("health-success-cache-secs", args.health_success_cache_secs),
        ("health-failure-cache-secs", args.health_failure_cache_secs),
        ("shutdown-grace-secs", args.shutdown_grace_secs),
    ] {
        if value == 0 {
            bail!("--{name} must be nonzero");
        }
        if tokio::time::Instant::now()
            .checked_add(Duration::from_secs(value))
            .is_none()
        {
            bail!("--{name} exceeds the deadline clock range");
        }
    }
    if limits.max_sandboxes == 0 {
        bail!("--max-sandboxes must be nonzero");
    }
    if limits.default_timeout > limits.max_timeout {
        bail!("--default-timeout-secs is above --max-timeout-secs");
    }

    if u32::try_from(limits.max_timeout.as_millis()).is_err() {
        bail!("--max-timeout-secs in milliseconds must fit u32");
    }
    let request_min = limits
        .max_stdin_bytes
        .checked_add(limits.max_argv_bytes)
        .and_then(|n| n.checked_add(64 * 1024))
        .context("request size minimum overflows")?;
    if limits.max_request_bytes < request_min {
        bail!(
            "--max-request-bytes must be at least max_stdin_bytes + max_argv_bytes + 64KiB ({request_min})"
        );
    }
    let response_min = limits
        .max_output_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(limits.max_argv_bytes))
        .and_then(|n| n.checked_add(64 * 1024))
        .context("--max-output-bytes response size minimum overflows")?;
    if limits.max_response_bytes < response_min {
        bail!(
            "--max-response-bytes must be at least 2 * --max-output-bytes + max_argv_bytes + 64KiB ({response_min})"
        );
    }
    if limits.max_list_response_bytes > limits.max_response_bytes {
        bail!("--max-list-response-bytes must not exceed --max-response-bytes");
    }
    if limits.max_list_page_size == 0 || limits.max_list_page_size > 1000 {
        bail!("--max-list-page-size must be between 1 and 1000");
    }
    Ok(limits)
}

fn group_id(name: &str) -> Result<u32> {
    let cname = CString::new(name).context("group name contains NUL")?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        bail!(
            "look up group {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        );
    }
    if result.is_null() {
        bail!(
            "group {name:?} does not exist; create it (groupadd --system {name}) or pass --socket-group ''"
        );
    }
    Ok(grp.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_and_zero_queue_are_valid() {
        let args = Args::try_parse_from(["kilnd"]).unwrap();
        let limits = validated_limits(&args).unwrap();
        assert_eq!(limits.max_connections, 64);
        assert_eq!(limits.max_request_bytes, 2 << 20);
        assert_eq!(limits.health_probe_timeout, Duration::from_secs(2));
        let args = Args::try_parse_from(["kilnd", "--max-queued-execs-per-sandbox", "0"]).unwrap();
        validated_limits(&args).unwrap();

        let mut args = Args::try_parse_from(["kilnd"]).unwrap();
        args.max_response_bytes = (2 * args.max_output_bytes) + (64 * 1024);
        assert!(
            validated_limits(&args)
                .unwrap_err()
                .to_string()
                .contains("max_argv_bytes")
        );
    }

    #[test]
    fn invalid_limits_fail_with_specific_diagnostics() {
        for flag in [
            "--max-connections",
            "--max-concurrent-rpcs",
            "--max-concurrent-health",
            "--max-concurrent-execs",
            "--max-queued-exec-stdin-bytes",
            "--max-streams-per-connection",
            "--max-request-bytes",
            "--max-response-bytes",
            "--max-list-response-bytes",
            "--max-list-page-size",
            "--max-output-bytes",
            "--max-sandboxes",
            "--default-timeout-secs",
            "--max-timeout-secs",
            "--health-probe-timeout-secs",
            "--health-success-cache-secs",
            "--health-failure-cache-secs",
            "--shutdown-grace-secs",
        ] {
            let args = Args::try_parse_from(["kilnd", flag, "0"]).unwrap();
            assert!(
                validated_limits(&args)
                    .unwrap_err()
                    .to_string()
                    .contains(flag),
                "{flag}"
            );
        }
        for (flag, value, diagnostic) in [
            ("--max-connections", "4294967296", "u32 semaphore"),
            (
                "--max-queued-exec-stdin-bytes",
                "4294967296",
                "u32 semaphore",
            ),
            (
                "--max-streams-per-connection",
                "4294967296",
                "u32 semaphore",
            ),
            (
                "--max-queued-execs-per-sandbox",
                "18446744073709551615",
                "overflows",
            ),
            (
                "--max-request-bytes",
                "1",
                "max_stdin_bytes + max_argv_bytes",
            ),
            ("--max-response-bytes", "1", "max-output-bytes"),
            ("--max-output-bytes", "18446744073709551615", "overflows"),
            ("--max-list-page-size", "1001", "between 1 and 1000"),
            ("--max-list-response-bytes", "5000000", "must not exceed"),
            ("--max-timeout-secs", "4294968", "milliseconds must fit u32"),
            ("--default-timeout-secs", "3601", "above --max-timeout-secs"),
        ] {
            let args = Args::try_parse_from(["kilnd", flag, value]).unwrap();
            assert!(
                validated_limits(&args)
                    .unwrap_err()
                    .to_string()
                    .contains(diagnostic),
                "{flag} {value}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_config_has_no_state_or_socket_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let mut args = Args::try_parse_from(["kilnd", "--max-connections", "0"]).unwrap();
        args.state_dir = temp.path().join("state");
        args.socket = temp.path().join("run/kilnd.sock");
        assert!(
            run(args)
                .await
                .unwrap_err()
                .to_string()
                .contains("--max-connections")
        );
        assert!(!temp.path().join("state").exists());
        assert!(!temp.path().join("run").exists());
    }
}
