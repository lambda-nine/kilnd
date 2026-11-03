use std::ffi::CString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use kilnd::manager::{Limits, Manager};
use kilnd::model::Id128;
use kilnd::runtime::Runtime;
use kilnd::runtime::firecracker::FirecrackerRuntime;
use kilnd::runtime::kiln::KilnRuntime;
use kilnd::store::Store;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
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
    /// Private root-helper Unix socket (absolute path).
    #[arg(long, default_value = "/run/kilnd-helper/helper.sock")]
    helper_socket: PathBuf,
    /// Execution timeout when a request gives none, in seconds.
    #[arg(long, default_value_t = 60)]
    default_timeout_secs: u64,
    /// Longest execution timeout a request may ask for, in seconds.
    #[arg(long, default_value_t = 3600)]
    max_timeout_secs: u64,
    /// Bytes of stdout and of stderr kept per execution.
    #[arg(long, default_value_t = 1 << 20)]
    max_output_bytes: usize,
    /// Persist captured bytes, metadata only (recommended), or no output evidence.
    #[arg(long, value_enum, default_value_t = kilnd::retention::OutputStorage::Full)]
    output_storage: kilnd::retention::OutputStorage,
    #[arg(long, default_value_t = 604800)]
    execution_max_age_secs: u64,
    #[arg(long, default_value_t = 10000)]
    execution_max_count: u32,
    #[arg(long, default_value_t = 604800)]
    deleted_sandbox_max_age_secs: u64,
    #[arg(long, default_value_t = 1000)]
    deleted_sandbox_max_count: u32,
    #[arg(long, default_value_t = 60)]
    prune_interval_secs: u64,
    /// Durable sandbox reservations retained at once, including lost and ambiguous rows.
    #[arg(long, default_value_t = 32)]
    max_sandboxes: u32,
    /// Aggregate memory promised to durably reserved sandboxes on this node.
    #[arg(long, default_value_t = 3_u64 << 30)]
    max_node_memory_bytes: u64,
    /// Aggregate process/thread slots promised to durably reserved sandboxes.
    #[arg(long, default_value_t = 2048)]
    max_node_pids: u64,
    /// Aggregate disk quota promised to durably reserved sandboxes on this node.
    #[arg(long, default_value_t = 16_u64 << 30)]
    max_node_disk_bytes: u64,
    /// Local policy for host CPU millis an allocation-token backend reserves. Kiln reserves none.
    #[arg(long, default_value_t = 3000)]
    max_node_host_cpu_millis: u64,
    /// Local policy for vCPU slots an allocation-token backend reserves. Kiln reserves none.
    #[arg(long, default_value_t = 3)]
    max_node_virtual_cpu_slots: u64,
    /// Local policy for host PIDs an allocation-token backend reserves. Kiln reserves none.
    #[arg(long, default_value_t = 96)]
    max_node_host_pids: u64,
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
    /// The execution backend. Until B7, `firecracker` runs only as the isolated test
    /// deployment named by --firecracker-test-deployment, never in production.
    #[arg(long, value_enum, default_value_t = Backend::Kiln)]
    backend: Backend,
    /// deploy/firecracker-test/deployment.json: the isolated test deployment's paths,
    /// which must match this daemon's flags. Required with --backend firecracker.
    #[arg(long)]
    firecracker_test_deployment: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Creates this instance's private state as its own account, if it doesn't exist yet,
    /// and prints the durable instance ID to enroll. Safe to repeat, and to run as root,
    /// which gives up every privilege before opening anything in the directory. It serves
    /// nothing. An existing database of an older schema is upgraded, as a start would.
    InitState {
        /// The instance's state directory.
        #[arg(long)]
        state_dir: PathBuf,
        /// The account that will own the directory and run the daemon.
        #[arg(long)]
        account: String,
    },
    /// Attaches to the helper once as this process, then exits. It passes only when run by
    /// the enrolled account, in the enrolled unit's cgroup, from the enrolled image.
    CheckAttachment {
        #[arg(long, default_value = "/var/lib/kilnd")]
        state_dir: PathBuf,
        #[arg(long, default_value = "/run/kilnd-helper/helper.sock")]
        helper_socket: PathBuf,
        /// Stay attached, holding the state lock, until SIGTERM or SIGINT: as a daemon would.
        #[arg(long)]
        hold: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    Kiln,
    Firecracker,
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
    let outcome = match args.command {
        Some(Command::InitState { state_dir, account }) => init_state(&state_dir, &account)
            .map(|instance| println!("{instance}"))
            .with_context(|| format!("initialize {}", state_dir.display())),
        Some(Command::CheckAttachment {
            state_dir,
            helper_socket,
            hold,
        }) => runtime.block_on(kilnd::attachment_check::run(
            &state_dir,
            helper_socket,
            hold,
        )),
        None => runtime.block_on(run(args)),
    };
    match outcome {
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
    if unsafe { libc::geteuid() } == 0 {
        bail!("kilnd refuses root; run as the kilnd system user behind kilnd-helper");
    }
    if !args.helper_socket.is_absolute() {
        bail!("--helper-socket must be absolute");
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

    // The backend is settled before anything is opened: a refused test deployment
    // touches no state.
    let deployment = selected_deployment(&args)?;

    // Store::open takes the state-directory lock before opening SQLite. Bind
    // then takes the socket-directory lock and reserves the endpoint. Both
    // ownership domains must be established before reconciliation mutates
    // durable state or invokes kiln.
    let store = Store::open(&args.state_dir)?;
    let state_directory = store
        .state_directory_identity()?
        .context("on-disk store has no state-directory identity")?;
    let socket = kilnd::server::bind_away_from(&args.socket, gid, Some(state_directory)).await?;
    match deployment {
        None => {
            let runtime = KilnRuntime::new(args.helper_socket.clone());
            serve_with(args, store, socket, runtime, limits).await
        }
        Some(deployment) => {
            warn!(
                deployment = %deployment.deployment,
                profile = %deployment.profile,
                "serving the isolated Firecracker test deployment; this is not a production configuration"
            );
            let identity = store.identity()?;
            let runtime = FirecrackerRuntime::new(
                args.helper_socket.clone(),
                identity.instance_id,
                identity.database_uuid,
            );
            serve_with(args, store, socket, runtime, limits).await
        }
    }
}

/// Kiln, or until B7 the isolated Firecracker test deployment and nothing else.
fn selected_deployment(args: &Args) -> Result<Option<kilnd::test_deployment::TestDeployment>> {
    match (args.backend, &args.firecracker_test_deployment) {
        (Backend::Kiln, None) => Ok(None),
        (Backend::Kiln, Some(_)) => {
            bail!("--firecracker-test-deployment needs --backend firecracker")
        }
        (Backend::Firecracker, None) => bail!(
            "--backend firecracker runs only as the isolated test deployment until B7: pass --firecracker-test-deployment"
        ),
        (Backend::Firecracker, Some(path)) => {
            let deployment = kilnd::test_deployment::TestDeployment::read(path)?;
            deployment.check_daemon(&args.socket, &args.state_dir, &args.helper_socket)?;
            Ok(Some(deployment))
        }
    }
}

/// The one daemon composition, for whichever backend `run` selected (design 9.1).
async fn serve_with<R: Runtime>(
    args: Args,
    store: Store,
    socket: kilnd::server::BoundSocket,
    runtime: R,
    limits: Limits,
) -> Result<()> {
    let manager = Arc::new(Manager::new(runtime, store, limits));
    let r = manager
        .reconcile()
        .await
        .context("startup reconciliation")?;
    info!(
        backend = manager.runtime().name(),
        gc_removed = r.gc_removed.len(),
        recovered = r.recovered.len(),
        lost = r.lost.len(),
        failed = r.failed.len(),
        deleted = r.deleted.len(),
        still_deleting = r.still_deleting.len(),
        interrupted_executions = r.interrupted_executions,
        unmanaged = r.unmanaged.len(),
        released = r.released.len(),
        quarantined = r.quarantined.len(),
        admission_blocked = r.admission_blocked,
        "reconciled with the backend"
    );

    manager.prune().context("startup history prune")?;
    let prune_manager = manager.clone();
    let prune_cancel = tokio_util::sync::CancellationToken::new();
    let stop_prune = prune_cancel.clone();
    let prune_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(args.prune_interval_secs));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = stop_prune.cancelled() => break,
                _ = interval.tick() => if let Err(error) = prune_manager.prune() {
                    error!(%error, "history prune failed");
                }
            }
        }
    });
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
    prune_cancel.cancel();
    prune_task.await.context("join history pruner")?;
    info!("stopped");
    result
}

/// The one way an instance's identity comes to exist. Enrollment needs this ID before the
/// unit may start, so it can't wait for the daemon's first start to generate one.
fn init_state(state_dir: &Path, account: &str) -> Result<Id128> {
    if !state_dir.is_absolute() {
        bail!("--state-dir must be absolute");
    }
    let (uid, gid) = account_ids(account)?;
    if uid == 0 {
        bail!("kilnd refuses root; name the instance's own account");
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        prepare_state_as_root(state_dir, uid, gid)?;
        drop_privileges(uid, gid)?;
    } else if euid != uid {
        bail!("run this as root or as {account}");
    }
    let store = Store::open(state_dir)?;
    Ok(store.identity()?.instance_id)
}

/// Root touches only the final directory, below a path only root controls. Everything
/// inside it is left for the account to create after root is gone.
#[cfg(target_os = "linux")]
fn prepare_state_as_root(state_dir: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, fchown};
    if state_dir
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        bail!("--state-dir must not contain '..'");
    }
    let parent = state_dir
        .parent()
        .context("--state-dir has no parent")?
        .canonicalize()
        .context("--state-dir's parent must exist")?;
    for ancestor in parent.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!("{} is not root's alone", ancestor.display());
        }
    }
    let created = match std::fs::DirBuilder::new().mode(0o700).create(state_dir) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error).context("create the state directory"),
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(state_dir)
        .context("open the state directory without following links")?;
    if created {
        fchown(&directory, Some(uid), Some(gid)).context("give the account its directory")?;
    } else if directory.metadata()?.uid() != uid {
        bail!("the state directory belongs to another account");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_state_as_root(_: &Path, _: u32, _: u32) -> Result<()> {
    bail!("kilnd runs as a service on Linux only");
}

/// Permanently becomes the account, with no supplementary groups.
#[cfg(target_os = "linux")]
fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    // SAFETY: none of these has a precondition, and the null list has length zero. The
    // process is single-threaded here, and libc applies credentials to every thread anyway.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(uid, uid, uid) != 0
        {
            return Err(std::io::Error::last_os_error()).context("drop to the account");
        }
        if libc::geteuid() != uid || libc::getegid() != gid || libc::setuid(0) == 0 {
            bail!("root privileges were not fully dropped");
        }
    }
    std::env::set_current_dir("/").context("leave the caller's directory")
}

#[cfg(not(target_os = "linux"))]
fn drop_privileges(_: u32, _: u32) -> Result<()> {
    bail!("kilnd runs as a service on Linux only");
}

fn validated_limits(args: &Args) -> Result<Limits> {
    for age in [
        args.execution_max_age_secs,
        args.deleted_sandbox_max_age_secs,
    ] {
        if age
            .checked_mul(1000)
            .and_then(|n| i64::try_from(n).ok())
            .is_none()
        {
            bail!("retention age exceeds timestamp range");
        }
    }
    let limits = Limits {
        retention: kilnd::retention::Retention {
            execution_max_age_secs: args.execution_max_age_secs,
            execution_max_count: args.execution_max_count,
            sandbox_max_age_secs: args.deleted_sandbox_max_age_secs,
            sandbox_max_count: args.deleted_sandbox_max_count,
            prune_interval_secs: args.prune_interval_secs,
            output_storage: args.output_storage,
        },
        default_timeout: Duration::from_secs(args.default_timeout_secs),
        max_timeout: Duration::from_secs(args.max_timeout_secs),
        max_output_bytes: args.max_output_bytes,
        max_sandboxes: args.max_sandboxes,
        max_node_memory_bytes: args.max_node_memory_bytes,
        max_node_pids: args.max_node_pids,
        max_node_disk_bytes: args.max_node_disk_bytes,
        max_node_host_cpu_millis: args.max_node_host_cpu_millis,
        max_node_virtual_cpu_slots: args.max_node_virtual_cpu_slots,
        max_node_host_pids: args.max_node_host_pids,
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
        ("prune-interval-secs", args.prune_interval_secs),
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
    for (name, value) in [
        ("max-node-memory-bytes", limits.max_node_memory_bytes),
        ("max-node-pids", limits.max_node_pids),
        ("max-node-disk-bytes", limits.max_node_disk_bytes),
    ] {
        if value == 0 {
            bail!("--{name} must be nonzero");
        }
    }
    for (name, default, node_limit) in [
        (
            "memory",
            limits.default_memory_bytes,
            limits.max_node_memory_bytes,
        ),
        ("pids", u64::from(limits.default_pids), limits.max_node_pids),
        (
            "disk",
            limits.default_disk_bytes,
            limits.max_node_disk_bytes,
        ),
    ] {
        if default > node_limit {
            bail!("default sandbox {name} {default} exceeds node budget {node_limit}");
        }
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
    if args.max_timeout_secs > 3600 {
        bail!("--max-timeout-secs exceeds helper maximum of 3600");
    }
    if args.max_output_bytes > (1 << 20) {
        bail!("--max-output-bytes exceeds helper maximum of 1 MiB");
    }
    Ok(limits)
}

/// A named account's UID and primary GID, from the system's account database.
fn account_ids(name: &str) -> Result<(u32, u32)> {
    let cname = CString::new(name).context("account name contains NUL")?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        bail!("no such account: {name}");
    }
    Ok((pwd.pw_uid, pwd.pw_gid))
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
    fn firecracker_runs_only_as_the_isolated_test_deployment() {
        let deployment = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/firecracker-test/deployment.json");
        let parse = |extra: &[&str]| {
            let mut argv = vec!["kilnd"];
            argv.extend_from_slice(extra);
            selected_deployment(&Args::try_parse_from(argv).unwrap())
        };
        assert!(parse(&[]).unwrap().is_none());
        assert!(parse(&["--backend", "firecracker"]).is_err());
        let file = deployment.to_str().unwrap();
        assert!(parse(&["--firecracker-test-deployment", file]).is_err());
        // The production paths are the defaults, so the file alone is refused there.
        assert!(
            parse(&[
                "--backend",
                "firecracker",
                "--firecracker-test-deployment",
                file
            ])
            .is_err()
        );
        let selected = parse(&[
            "--backend",
            "firecracker",
            "--firecracker-test-deployment",
            file,
            "--socket",
            "/run/kilnd-fctest/kilnd.sock",
            "--state-dir",
            "/var/lib/kilnd-fctest",
            "--helper-socket",
            "/run/kilnd-fctest-helper/helper.sock",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(selected.deployment, "isolated-test");
    }

    #[test]
    fn default_limits_and_zero_queue_are_valid() {
        let args = Args::try_parse_from(["kilnd"]).unwrap();
        let limits = validated_limits(&args).unwrap();
        assert_eq!(limits.max_connections, 64);
        assert_eq!(limits.max_request_bytes, 2 << 20);
        assert_eq!(limits.health_probe_timeout, Duration::from_secs(2));
        assert_eq!(limits.max_node_memory_bytes, 3 << 30);
        assert_eq!(limits.max_node_pids, 2048);
        assert_eq!(limits.max_node_disk_bytes, 16 << 30);
        assert_eq!(limits.max_node_host_cpu_millis, 3000);
        assert_eq!(limits.max_node_virtual_cpu_slots, 3);
        assert_eq!(limits.max_node_host_pids, 96);
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
            "--max-node-memory-bytes",
            "--max-node-pids",
            "--max-node-disk-bytes",
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
            (
                "--max-node-memory-bytes",
                "536870911",
                "default sandbox memory",
            ),
            ("--max-node-pids", "127", "default sandbox pids"),
            (
                "--max-node-disk-bytes",
                "1073741823",
                "default sandbox disk",
            ),
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

    fn own_account_name() -> String {
        // SAFETY: the static record is read before anything else can replace it.
        unsafe {
            let record = libc::getpwuid(libc::geteuid());
            assert!(!record.is_null());
            std::ffi::CStr::from_ptr((*record).pw_name)
                .to_str()
                .unwrap()
                .to_string()
        }
    }

    /// The other half of B3F-01: the daemon's own open reads the ID init-state printed, so
    /// the ID enrolled can only be the one the daemon will use.
    #[test]
    fn b3f_01_init_state_prints_the_identity_the_daemon_will_use() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let account = own_account_name();
        let first = init_state(&state, &account).unwrap();
        assert_eq!(init_state(&state, &account).unwrap(), first, "repeatable");
        assert_eq!(
            Store::open(&state).unwrap().identity().unwrap().instance_id,
            first
        );
        let other = temp.path().join("other");
        assert_ne!(init_state(&other, &account).unwrap(), first);
    }

    #[test]
    fn b3f_01_init_state_refuses_what_it_cannot_do_safely() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let refused = |dir: &Path, account: &str| {
            let error = init_state(dir, account).unwrap_err().to_string();
            assert!(!temp.path().join("state").exists(), "{error}");
            error
        };
        assert!(refused(Path::new("relative"), "root").contains("absolute"));
        assert!(refused(&state, "no-such-account-b3f").contains("no such account"));
        assert!(refused(&state, "root").contains("refuses root"));
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            // Another account's state can't be made from here. `daemon` exists on both
            // Linux and macOS; the account is only looked up.
            assert!(refused(&state, "daemon").contains("as root or as daemon"));
        }
    }

    /// A live daemon's lock also keeps init-state out of its database.
    #[test]
    fn b3f_01_init_state_never_shares_a_state_directory_with_a_daemon() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let _daemon = Store::open(&state).unwrap();
        init_state(&state, &own_account_name()).unwrap_err();
    }

    #[test]
    fn subcommands_keep_the_daemons_flags_their_own() {
        let args = Args::try_parse_from([
            "kilnd",
            "init-state",
            "--state-dir",
            "/var/lib/kilnd-a",
            "--account",
            "kilnd-a",
        ])
        .unwrap();
        assert!(matches!(args.command, Some(Command::InitState { .. })));
        assert_eq!(args.state_dir, PathBuf::from("/var/lib/kilnd"));
        assert!(Args::try_parse_from(["kilnd"]).unwrap().command.is_none());
        assert!(Args::try_parse_from(["kilnd", "init-state", "--account", "a"]).is_err());
        let check = Args::try_parse_from(["kilnd", "check-attachment"]).unwrap();
        assert!(matches!(
            check.command,
            Some(Command::CheckAttachment { .. })
        ));
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
