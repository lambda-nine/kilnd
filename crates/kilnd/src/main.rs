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
#[cfg(feature = "firecracker-test-deployment")]
use kilnd::runtime::firecracker::FirecrackerRuntime;
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
    /// Connection slots, of --max-connections, held back for Health, GetSandbox and
    /// DeleteSandbox; each UID may hold one.
    #[arg(long, default_value_t = 4)]
    reserved_connections: usize,
    /// General connection slots one UID may hold at once.
    #[arg(long, default_value_t = 32)]
    max_connections_per_uid: usize,
    /// How long an accepted connection may take to send the HTTP/2 client preface
    /// before it is closed and its slot released, in milliseconds.
    #[arg(long, default_value_t = 5000)]
    connection_preface_timeout_ms: u64,
    /// Simultaneous ordinary RPC handlers, after message decoding.
    #[arg(long, default_value_t = 64)]
    max_concurrent_rpcs: usize,
    /// Ordinary RPC handlers one UID may hold at once.
    #[arg(long, default_value_t = 32)]
    max_concurrent_rpcs_per_uid: usize,
    /// Reserved GetSandbox and DeleteSandbox handlers, used once the ordinary RPCs are
    /// full; each UID may hold one.
    #[arg(long, default_value_t = 4)]
    max_concurrent_cleanup: usize,
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
    /// Longest max_lifetime a create may ask for, in seconds. 0: no cap.
    #[arg(long, default_value_t = 604_800)]
    max_sandbox_lifetime_secs: u64,
    /// Longest idle_timeout a create may ask for, in seconds. 0: no cap.
    #[arg(long, default_value_t = 86_400)]
    max_sandbox_idle_secs: u64,
    /// max_lifetime for a zero field of a create's expiry policy, in seconds. Never
    /// applies to a create that sends no policy. 0: never expires.
    #[arg(long, default_value_t = 0)]
    default_sandbox_lifetime_secs: u64,
    /// idle_timeout for a zero field of a create's expiry policy, in seconds. Never
    /// applies to a create that sends no policy. 0: never expires.
    #[arg(long, default_value_t = 0)]
    default_sandbox_idle_secs: u64,
    /// After startup, how long no idle expiry fires, so clients can renew, in seconds.
    #[arg(long, default_value_t = 60)]
    expiry_restart_grace_secs: u64,
    /// A pending expiry delete this old makes Health DEGRADED, in seconds.
    #[arg(long, default_value_t = 600)]
    expiry_degraded_after_secs: u64,
    /// How often the expiry sweeper rescans the boot clock, in seconds (1 to 300).
    #[arg(long, default_value_t = 30)]
    expiry_rescan_secs: u64,
    /// Removals of expiry-owned sandboxes running at once, including client Deletes
    /// that follow one (1 to 16).
    #[arg(long, default_value_t = 4)]
    max_concurrent_expiry_deletes: usize,
    /// On SIGTERM, how long running requests may finish before executions are
    /// canceled, in seconds.
    #[arg(long, default_value_t = 30)]
    shutdown_grace_secs: u64,
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// The execution backend. Until B7, `firecracker` exists only in a build with the
    /// `firecracker-test-deployment` feature, and runs only as the isolated test
    /// deployment named by --firecracker-test-deployment, never in production.
    #[arg(long, value_enum, default_value_t = Backend::Kiln)]
    backend: Backend,
    /// deploy/firecracker-test/deployment.json: the isolated test deployment's paths,
    /// which must match this daemon's flags, and its account, group and unit, which
    /// must match this process. Required with --backend firecracker. Only in a build
    /// with the `firecracker-test-deployment` feature.
    #[cfg(feature = "firecracker-test-deployment")]
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
    /// B6-BI-01's build boundary: a default (release, installed) build has no such value.
    #[cfg(feature = "firecracker-test-deployment")]
    Firecracker,
}

/// What `selected_deployment` can select besides kiln: the isolated test deployment in a
/// feature build, nothing at all otherwise.
#[cfg(feature = "firecracker-test-deployment")]
type Selected = kilnd::test_deployment::TestDeployment;
#[cfg(not(feature = "firecracker-test-deployment"))]
type Selected = std::convert::Infallible;

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
    let deployment = selected_deployment(&args, gid)?;

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
        #[cfg(not(feature = "firecracker-test-deployment"))]
        Some(never) => match never {},
        #[cfg(feature = "firecracker-test-deployment")]
        Some(deployment) => {
            tracing::warn!(
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
            // B7 RTC-14: every attachment reports the highest token this database holds.
            runtime.record_token(store.highest_fenced_token(identity.instance_id)?);
            serve_with(args, store, socket, runtime, limits).await
        }
    }
}

/// Kiln, and in a default build nothing else.
#[cfg(not(feature = "firecracker-test-deployment"))]
fn selected_deployment(args: &Args, _socket_gid: Option<u32>) -> Result<Option<Selected>> {
    match args.backend {
        Backend::Kiln => Ok(None),
    }
}

/// Kiln, or until B7 the isolated Firecracker test deployment and nothing else: its
/// paths are this daemon's flags, and its account, socket group and unit are what this
/// process observably is (B6-BI-01), all before any state is opened.
#[cfg(feature = "firecracker-test-deployment")]
fn selected_deployment(args: &Args, socket_gid: Option<u32>) -> Result<Option<Selected>> {
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
            deployment.check_process(socket_gid)?;
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
    let clock = Arc::new(kilnd::expiry::SystemClock::new().context("read the kernel boot ID")?);
    let manager = Arc::new(Manager::with_clock(runtime, store, limits, clock));
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

    // After reconciliation and before the sweeper, admission or any prune (design 2.3).
    let rebased = manager
        .rebase_expiry_clocks()
        .context("rebase expiry clocks from an earlier boot")?;
    if rebased != 0 {
        info!(rows = rebased, "rebased expiry clocks from an earlier boot");
    }
    manager.prune().context("startup history prune")?;
    let expiry_task = manager.start_expiry().context("start the expiry sweeper")?;
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
    let sweeper = manager.clone();
    let result = kilnd::server::serve(
        manager,
        socket,
        shutdown,
        Duration::from_secs(args.shutdown_grace_secs),
    )
    .await;
    prune_cancel.cancel();
    prune_task.await.context("join history pruner")?;
    // serve began shutdown unless it failed first; either way the sweeper stops.
    sweeper.begin_shutdown();
    expiry_task.await.context("join the expiry sweeper")?;
    drop(sweeper);
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
        reserved_connections: args.reserved_connections,
        max_connections_per_uid: args.max_connections_per_uid,
        connection_preface_timeout: Duration::from_millis(args.connection_preface_timeout_ms),
        max_concurrent_rpcs: args.max_concurrent_rpcs,
        max_concurrent_rpcs_per_uid: args.max_concurrent_rpcs_per_uid,
        max_concurrent_cleanup: args.max_concurrent_cleanup,
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
        expiry: kilnd::expiry::ExpiryLimits {
            max_lifetime_ms: secs_ms(args.max_sandbox_lifetime_secs, "max-sandbox-lifetime-secs")?,
            max_idle_ms: secs_ms(args.max_sandbox_idle_secs, "max-sandbox-idle-secs")?,
            default_lifetime_ms: secs_ms(
                args.default_sandbox_lifetime_secs,
                "default-sandbox-lifetime-secs",
            )?,
            default_idle_ms: secs_ms(args.default_sandbox_idle_secs, "default-sandbox-idle-secs")?,
            restart_grace: Duration::from_secs(args.expiry_restart_grace_secs),
            degraded_after: Duration::from_secs(args.expiry_degraded_after_secs),
            rescan: Duration::from_secs(args.expiry_rescan_secs),
            max_concurrent_deletes: args.max_concurrent_expiry_deletes,
        },
        ..Limits::default()
    };
    validate_expiry(&limits.expiry, args)?;
    for (name, value) in [
        ("max-connections", limits.max_connections),
        ("reserved-connections", limits.reserved_connections),
        ("max-connections-per-uid", limits.max_connections_per_uid),
        ("max-concurrent-rpcs", limits.max_concurrent_rpcs),
        (
            "max-concurrent-rpcs-per-uid",
            limits.max_concurrent_rpcs_per_uid,
        ),
        ("max-concurrent-cleanup", limits.max_concurrent_cleanup),
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
    // B6-BI-03 and B7 milestone 2 (HIGH-2): the reserve leaves a general pool, and no
    // one UID's share is the whole general pool, the whole connection budget with its
    // reserved slot, or every ordinary RPC. Strictly: equality is refused.
    if let Err(error) = kilnd::admission::validate_ingress(&limits) {
        bail!("{error}");
    }
    if !(100..=60_000).contains(&args.connection_preface_timeout_ms) {
        bail!("--connection-preface-timeout-ms must be 100 to 60000");
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
/// Seconds as milliseconds that fit the store's signed 64-bit columns and every
/// boottime sum.
fn secs_ms(secs: u64, name: &str) -> Result<u64> {
    secs.checked_mul(1000)
        .filter(|&ms| i64::try_from(ms).is_ok_and(|ms| ms <= i64::MAX / 4))
        .with_context(|| format!("--{name} is out of range"))
}

/// Design section 7's expiry rules, checked before any state is opened.
fn validate_expiry(e: &kilnd::expiry::ExpiryLimits, args: &Args) -> Result<()> {
    let min = kilnd::expiry::MIN_EXPIRY_MS;
    for (name, max, default) in [
        ("sandbox-lifetime", e.max_lifetime_ms, e.default_lifetime_ms),
        ("sandbox-idle", e.max_idle_ms, e.default_idle_ms),
    ] {
        if max != 0 && max < min {
            bail!(
                "--max-{name}-secs must be 0 (no cap) or at least {} s",
                min / 1000
            );
        }
        if default != 0 && default < min {
            bail!(
                "--default-{name}-secs must be 0 (never) or at least {} s",
                min / 1000
            );
        }
        if default != 0 && max != 0 && default > max {
            bail!("--default-{name}-secs is above --max-{name}-secs");
        }
    }
    if !(1..=300).contains(&args.expiry_rescan_secs) {
        bail!("--expiry-rescan-secs must be 1 to 300");
    }
    if !(1..=16).contains(&e.max_concurrent_deletes) {
        bail!("--max-concurrent-expiry-deletes must be 1 to 16");
    }
    for (name, value) in [
        ("expiry-restart-grace-secs", args.expiry_restart_grace_secs),
        (
            "expiry-degraded-after-secs",
            args.expiry_degraded_after_secs,
        ),
    ] {
        if value > 86_400 {
            bail!("--{name} must be at most 86400");
        }
    }
    if args.expiry_degraded_after_secs == 0 {
        bail!("--expiry-degraded-after-secs must be nonzero");
    }
    Ok(())
}

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

    /// B6-BI-01's build boundary: a default build refuses both flags at argument parsing.
    #[cfg(not(feature = "firecracker-test-deployment"))]
    #[test]
    fn b6_bi_01_a_default_build_has_no_firecracker_flags() {
        for argv in [
            &["kilnd", "--backend", "firecracker"][..],
            &[
                "kilnd",
                "--firecracker-test-deployment",
                "/tmp/deployment.json",
            ],
            &[
                "kilnd",
                "--backend",
                "firecracker",
                "--firecracker-test-deployment",
                "/tmp/deployment.json",
            ],
        ] {
            assert!(Args::try_parse_from(argv).is_err(), "{argv:?} parsed");
        }
        let args = Args::try_parse_from(["kilnd", "--backend", "kiln"]).unwrap();
        assert!(selected_deployment(&args, None).unwrap().is_none());
    }

    #[cfg(feature = "firecracker-test-deployment")]
    #[test]
    fn firecracker_runs_only_as_the_isolated_test_deployment() {
        let deployment = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/firecracker-test/deployment.json");
        let parse = |extra: &[&str]| {
            let mut argv = vec!["kilnd"];
            argv.extend_from_slice(extra);
            selected_deployment(&Args::try_parse_from(argv).unwrap(), None)
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
        // The right paths are not enough: this test process is not the deployment's
        // account, group or unit (B6-BI-01), so the file is refused here too.
        let error = parse(&[
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
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("kilnd-fctest") && !error.contains("differs from"),
            "{error}"
        );
    }

    #[test]
    fn expiry_flags_default_to_never_and_are_validated_before_state() {
        let args = Args::try_parse_from(["kilnd"]).unwrap();
        let limits = validated_limits(&args).unwrap();
        assert_eq!(limits.expiry, kilnd::expiry::ExpiryLimits::default());
        assert_eq!(limits.expiry.default_lifetime_ms, 0);
        assert_eq!(limits.expiry.default_idle_ms, 0);
        for (argv, ok) in [
            (&["--default-sandbox-idle-secs", "60"][..], true),
            (
                &[
                    "--max-sandbox-idle-secs",
                    "0",
                    "--default-sandbox-idle-secs",
                    "999999",
                ],
                true,
            ),
            (&["--default-sandbox-idle-secs", "86401"], false),
            (&["--default-sandbox-lifetime-secs", "9"], false),
            (&["--max-sandbox-lifetime-secs", "5"], false),
            (&["--max-sandbox-lifetime-secs", "0"], true),
            (&["--expiry-rescan-secs", "0"], false),
            (&["--expiry-rescan-secs", "301"], false),
            (&["--max-concurrent-expiry-deletes", "0"], false),
            (&["--max-concurrent-expiry-deletes", "17"], false),
            (&["--max-concurrent-expiry-deletes", "16"], true),
            (&["--expiry-degraded-after-secs", "0"], false),
            (&["--expiry-restart-grace-secs", "0"], true),
            (
                &["--max-sandbox-lifetime-secs", "18446744073709551615"],
                false,
            ),
        ] {
            let mut full = vec!["kilnd"];
            full.extend_from_slice(argv);
            let args = Args::try_parse_from(full).unwrap();
            assert_eq!(validated_limits(&args).is_ok(), ok, "{argv:?}");
        }
    }

    #[test]
    fn default_limits_and_zero_queue_are_valid() {
        let args = Args::try_parse_from(["kilnd"]).unwrap();
        let limits = validated_limits(&args).unwrap();
        assert_eq!(limits.max_connections, 64);
        assert_eq!(limits.reserved_connections, 4);
        assert_eq!(limits.max_connections_per_uid, 32);
        assert_eq!(limits.connection_preface_timeout, Duration::from_secs(5));
        assert_eq!(limits.max_concurrent_rpcs_per_uid, 32);
        assert_eq!(limits.max_concurrent_cleanup, 4);
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
            "--reserved-connections",
            "--max-connections-per-uid",
            "--max-concurrent-rpcs",
            "--max-concurrent-rpcs-per-uid",
            "--max-concurrent-cleanup",
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
            ("--reserved-connections", "64", "below --max-connections"),
            (
                "--max-connections-per-uid",
                "61",
                "general connection slots",
            ),
            (
                "--max-concurrent-rpcs-per-uid",
                "65",
                "below --max-concurrent-rpcs",
            ),
            // B7 milestone 2 (HIGH-2): equality is refused too.
            (
                "--max-concurrent-rpcs-per-uid",
                "64",
                "below --max-concurrent-rpcs",
            ),
            (
                "--max-connections-per-uid",
                "60",
                "general connection slots",
            ),
            ("--connection-preface-timeout-ms", "99", "100 to 60000"),
            ("--connection-preface-timeout-ms", "60001", "100 to 60000"),
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

    /// B7 milestone 2 (HIGH-2): the ingress invariants at their boundaries. Daybreak's
    /// `33/1/32` let one UID hold all 32 general slots and the only reserved slot; it is
    /// refused at startup, and one fewer per UID is accepted.
    #[test]
    fn b7m2_ingress_flags_are_refused_at_their_boundaries() {
        let check = |flags: &[&str]| {
            let mut argv = vec!["kilnd"];
            argv.extend_from_slice(flags);
            validated_limits(&Args::try_parse_from(argv).unwrap()).map_err(|e| e.to_string())
        };
        let connections = |total: &str, reserved: &str, per_uid: &str| {
            check(&[
                "--max-connections",
                total,
                "--reserved-connections",
                reserved,
                "--max-connections-per-uid",
                per_uid,
            ])
        };
        let refused = connections("33", "1", "32").unwrap_err();
        assert!(
            refused.contains(
                "--max-connections-per-uid (32) must be below the general connection slots"
            ),
            "{refused}"
        );
        connections("33", "1", "31").unwrap();
        assert!(connections("64", "4", "60").is_err());
        connections("64", "4", "59").unwrap();
        // The smallest accepted budget: one reserved slot, one general slot per UID and
        // one more general slot for everyone else.
        connections("3", "1", "1").unwrap();
        for (total, reserved, per_uid) in [("2", "1", "1"), ("3", "2", "1"), ("3", "3", "1")] {
            assert!(
                connections(total, reserved, per_uid).is_err(),
                "{total}/{reserved}/{per_uid}"
            );
        }
        let refused = connections("33", "0", "16").unwrap_err();
        assert!(refused.contains("--reserved-connections"), "{refused}");
        let rpcs = |total: &str, per_uid: &str| {
            check(&[
                "--max-concurrent-rpcs",
                total,
                "--max-concurrent-rpcs-per-uid",
                per_uid,
            ])
        };
        let refused = rpcs("8", "8").unwrap_err();
        assert!(
            refused.contains(
                "--max-concurrent-rpcs-per-uid (8) must be below --max-concurrent-rpcs (8)"
            ),
            "{refused}"
        );
        rpcs("8", "7").unwrap();
        let refused = check(&["--max-concurrent-cleanup", "0"]).unwrap_err();
        assert!(refused.contains("--max-concurrent-cleanup"), "{refused}");
        check(&["--max-concurrent-cleanup", "1"]).unwrap();
        // The defaults satisfy every invariant.
        check(&[]).unwrap();
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
