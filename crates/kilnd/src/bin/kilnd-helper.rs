//! Socket-activated root privilege boundary. No gRPC, DB, shell, or arbitrary argv.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{
    ffi::CString,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::PathBuf,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(long, default_value = "/usr/local/bin/kiln")]
    kiln: PathBuf,
    /// Root-owned Firecracker node policy. Absent, the group stays disabled. It serves
    /// B3 infrastructure only: no VM launches, and every profile stays refused until
    /// the production gate is lifted by a reviewed release.
    #[arg(long)]
    firecracker_policy: Option<PathBuf>,
    /// One-time creation of the node ledger named by the policy, then exit. An existing
    /// or partial ledger is refused; nothing else ever creates one.
    #[arg(long, requires = "firecracker_policy")]
    firecracker_init_ledger: bool,
    /// Serve the workspace checkpoint group (design section 4.3). Off by default.
    /// Required for kilnd's supported checkpoint opt-in and for maintaining existing
    /// checkpoint state (expiry, removal, reconciliation), also after kilnd's flag is
    /// off; without it the group answers Disabled.
    #[arg(long)]
    enable_checkpoints: bool,
    /// The serving lock, held while this helper serves and until every request it
    /// accepted has settled. `kilnd release-ambiguous` holds it for its whole proof; a
    /// helper that finds it held exits rather than serve.
    #[arg(long, default_value = kilnd::helper::DEFAULT_SERVE_LOCK)]
    serve_lock: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Root-only: names the Unix account, systemd unit and installed kilnd image allowed to
    /// serve an instance. Stop kilnd-helper first: this takes its node lock, and runs over
    /// no socket. scripts/add-instance.sh does that, with the ID `kilnd init-state` printed.
    Enroll {
        /// The instance's 32-digit hexadecimal ID.
        #[arg(long)]
        instance: String,
        /// The kilnd service unit that serves it, such as kilnd.service.
        #[arg(long)]
        unit: String,
        /// The unit's exact cgroup, when it isn't /system.slice/<unit>.
        #[arg(long)]
        cgroup: Option<String>,
        /// The instance's own Unix account, which no other instance may share. The default
        /// suits one instance; each further one needs its own, such as kilnd-<name>.
        #[arg(long, default_value = "kilnd")]
        user: String,
        /// The installed kilnd image that unit runs. scripts/upgrade.sh keeps it current.
        #[arg(long, default_value = kilnd::helper::firecracker::peer::DEFAULT_KILND_PATH)]
        kilnd: PathBuf,
        /// The root-owned Firecracker node policy naming the ledger and the enrollment limit.
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper stopped: prints every enrollment as JSON.
    Enrollments {
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper stopped: binds every enrolled instance to one installed image, in
    /// one transaction. Instances, accounts and units stay as they are.
    RefreshEnrollments {
        #[arg(long, default_value = kilnd::helper::firecracker::peer::DEFAULT_KILND_PATH)]
        kilnd: PathBuf,
        /// Prove the ledger and image would allow it, and write nothing.
        #[arg(long)]
        check: bool,
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper and every daemon stopped (B7, design 16.7): walks every enrolled
    /// instance's owned resources against the ledger and reads each daemon database
    /// read-only for its highest verified token. Writes a new report; destroys nothing.
    OfflineInventory {
        /// `<instance>=<path>` for every enrolled instance's kilnd.db.
        #[arg(long = "daemon-db", required = true)]
        daemon_db: Vec<String>,
        /// Where to write the report (new, mode 0600, in a root-owned directory).
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper stopped (B7 RTC-14): deletes the node's rollback faults after an
    /// explained, current offline inventory, raising each issue pointer past the daemons'
    /// verified tokens. Nothing else ever deletes a fault.
    ClearNodeFaults {
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper stopped: per-instance issue pointers, watermarks, retained rows
    /// and the last compaction, as JSON.
    LedgerStats {
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
    /// Root-only, helper running or stopped (M3-1): reads the helper's log on standard
    /// input, as `journalctl -u kilnd-helper -o cat` prints it, and prints each create's
    /// step waterfall from its timing line. It opens no ledger, socket or other file.
    CreateTimings {
        /// One allocation's create: its 32-digit hexadecimal ID.
        #[arg(long, conflicts_with = "last")]
        allocation: Option<String>,
        /// The last N creates in the log.
        #[arg(long, default_value_t = 1)]
        last: usize,
        /// Per step, its p50, p95 and max across the selected creates, instead.
        #[arg(long)]
        summary: bool,
    },
    /// Root-only, helper stopped: puts back the images that `enrollments` printed earlier.
    /// Refused unless the file names exactly the instances enrolled, unchanged.
    RestoreEnrollments {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, default_value = DEFAULT_POLICY)]
        policy: PathBuf,
    },
}

const DEFAULT_POLICY: &str = "/etc/kilnd/firecracker-node.json";
/// Far more than `max_enrolled_instances` rows could print.
const MAX_SNAPSHOT_BYTES: u64 = 1 << 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if unsafe { libc::geteuid() } != 0 {
        bail!("kilnd-helper must run as root");
    }
    unsafe {
        libc::umask(0o077);
    }
    if let Some(command) = &args.command {
        println!("{}", root_command(command)?);
        return Ok(());
    }
    // No request can select an executable; the administrator's configured
    // executable and every ancestor must be root-owned and not writable.
    let bin = kilnd::helper::trusted_kiln(&args.kiln)?;
    if args.firecracker_init_ledger {
        let path = args.firecracker_policy.as_deref().context("policy path")?;
        let policy = kilnd::helper::firecracker::read_policy(path, service_uid()?)
            .map_err(anyhow::Error::msg)
            .context("Firecracker node policy")?;
        return kilnd::helper::firecracker::provision_ledger(&policy)
            .map_err(anyhow::Error::msg)
            .context("provision node ledger");
    }
    // Held for the whole serve: past serve_with_groups, which returns only once every
    // request task it spawned has settled, and past the groups' own shutdown.
    match kilnd::helper::ServeLock::hold_while(&args.serve_lock, serve(&args, bin)).await {
        Ok(served) => served,
        Err(kilnd::helper::ServeLockError::Held(path)) => bail!(
            "{} is held: `kilnd release-ambiguous` (or another kilnd-helper) is running; \
             not serving until it has finished",
            path.display()
        ),
        Err(error) => Err(anyhow::Error::new(error).context("take the serving lock")),
    }
}

/// Everything kilnd-helper does while it holds the serving lock: systemd's socket, the
/// groups, the serve, and the groups' shutdown. It hands [`serve_groups`] what its three
/// steps return and nothing else; a test pins this body (`serve_is_only_its_steps`).
async fn serve(args: &Args, bin: PathBuf) -> Result<()> {
    let listener = systemd_listener()?;
    let service_uid = service_uid()?;
    let firecracker = start_firecracker(args, service_uid).await;
    serve_groups(
        listener,
        service_uid,
        bin,
        firecracker,
        args.enable_checkpoints,
        &mut std::io::stderr(),
    )
    .await
}

/// The one socket systemd passed, checked: fd 3, at the helper's path, nonblocking and
/// close-on-exec.
fn systemd_listener() -> Result<std::os::unix::net::UnixListener> {
    if std::env::var("LISTEN_PID")?.parse::<u32>()? != std::process::id()
        || std::env::var("LISTEN_FDS")? != "1"
    {
        bail!("exactly one systemd socket is required");
    }
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    listener.set_nonblocking(true)?;
    if listener.local_addr()?.as_pathname()
        != Some(std::path::Path::new("/run/kilnd-helper/helper.sock"))
    {
        bail!("unexpected systemd socket");
    }
    if unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(listener)
}

/// The Firecracker group, if root's policy names one and it starts. Its startup failure
/// never takes legacy kiln down with it: the group answers Disabled, and a configured
/// node with a bad ledger answers Unavailable.
async fn start_firecracker(
    args: &Args,
    service_uid: u32,
) -> Option<std::sync::Arc<kilnd::helper::firecracker::Node>> {
    match &args.firecracker_policy {
        None => None,
        Some(path) => match kilnd::helper::firecracker::read_policy(path, service_uid) {
            Err(error) => {
                eprintln!("kilnd-helper: Firecracker group disabled: {error}");
                None
            }
            Ok(policy) => {
                // SAFETY: geteuid has no preconditions.
                let helper_uid = unsafe { libc::geteuid() };
                let config = kilnd::helper::firecracker::production_config(policy, helper_uid);
                match kilnd::helper::firecracker::Node::start(config).await {
                    Ok(node) => Some(node),
                    Err(error) => {
                        eprintln!("kilnd-helper: Firecracker group disabled: {error}");
                        None
                    }
                }
            }
        },
    }
}

/// Everything after the socket is checked and the Firecracker group is up: the
/// checkpoint group's startup line to `out` (standard error in production), then
/// serving, then both groups' shutdown. A failed line write is the error, after the
/// Firecracker group is stopped, and nothing is served.
async fn serve_groups(
    listener: std::os::unix::net::UnixListener,
    service_uid: u32,
    bin: PathBuf,
    firecracker: Option<std::sync::Arc<kilnd::helper::firecracker::Node>>,
    enable_checkpoints: bool,
    out: &mut impl std::io::Write,
) -> Result<()> {
    // As with Firecracker, a checkpoint group that can't start never takes kiln down.
    // Exactly one startup line says which way it came up. A helper that can't write that
    // line doesn't serve, as when the eprintln! it replaced panicked.
    let kiln = bin.clone();
    let served_firecracker = firecracker.clone();
    let started = serve_after_checkpoint_line(
        enable_checkpoints,
        || {
            let workers = std::sync::Arc::new(kilnd::helper::checkpoint::KilnWorkers::new(kiln));
            kilnd::helper::checkpoint::Node::new(workers)
        },
        out,
        |checkpoint| async move {
            let stop = CancellationToken::new();
            let stopped = stop.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{SignalKind, signal};
                let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
                let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
                tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
                stopped.cancel();
            });
            let served = match tokio::net::UnixListener::from_std(listener) {
                Err(error) => Err(error.into()),
                Ok(listener) => kilnd::helper::serve_with_groups(
                    listener,
                    service_uid,
                    bin,
                    served_firecracker,
                    checkpoint.clone(),
                    stop,
                )
                .await
                .context("root helper"),
            };
            (served, checkpoint)
        },
    )
    .await;
    if let Some(node) = firecracker {
        node.shutdown();
    }
    let (served, checkpoint) =
        started.context("write the checkpoint group's startup line to standard error")?;
    // Every checkpoint worker is killed and reaped before the helper exits.
    if let Some(node) = checkpoint {
        node.shutdown().await;
    }
    served
}

/// Starts the checkpoint group ([`start_checkpoint_group`]) and only then, once its
/// startup line is written, runs `serve` with it. A failed write is the error, and
/// `serve` never runs.
async fn serve_after_checkpoint_line<N, E: std::fmt::Display, S: std::future::Future>(
    enabled: bool,
    construct: impl FnOnce() -> std::result::Result<N, E>,
    out: &mut impl std::io::Write,
    serve: impl FnOnce(Option<N>) -> S,
) -> std::io::Result<S::Output> {
    let checkpoint = start_checkpoint_group(enabled, construct, out)?;
    Ok(serve(checkpoint).await)
}

/// How the checkpoint group came up at startup.
#[derive(Debug, PartialEq, Eq)]
enum CheckpointGroup {
    Enabled,
    /// Started without `--enable-checkpoints`: the group answers Disabled.
    Off,
    /// Given the flag, but the group could not start: it answers Disabled too.
    Failed(String),
}

/// The helper's one startup line for its checkpoint group.
fn checkpoint_group_line(group: &CheckpointGroup) -> String {
    match group {
        CheckpointGroup::Enabled => "kilnd-helper: checkpoint group: enabled".into(),
        CheckpointGroup::Off => "kilnd-helper: checkpoint group: off (flag)".into(),
        CheckpointGroup::Failed(error) => {
            format!("kilnd-helper: checkpoint group: failed: {error}")
        }
    }
}

/// Starts the checkpoint group if `enabled`, by calling `construct` once, then writes
/// the one line for the outcome to `out` (standard error in production) exactly once.
/// Every outcome reaches that single write. If the write fails, so does the call: the
/// error comes back, any group it built is dropped unused, and the helper doesn't serve.
fn start_checkpoint_group<N, E: std::fmt::Display>(
    enabled: bool,
    construct: impl FnOnce() -> std::result::Result<N, E>,
    out: &mut impl std::io::Write,
) -> std::io::Result<Option<N>> {
    let (node, group) = if !enabled {
        (None, CheckpointGroup::Off)
    } else {
        match construct() {
            Ok(node) => (Some(node), CheckpointGroup::Enabled),
            Err(error) => (None, CheckpointGroup::Failed(error.to_string())),
        }
    };
    writeln!(out, "{}", checkpoint_group_line(&group))?;
    Ok(node)
}

/// One of root's ledger commands, which reach it by no socket and answer on stdout.
fn root_command(command: &Command) -> Result<String> {
    use kilnd::helper::firecracker as fc;
    let policy_at = |path: &PathBuf| -> Result<fc::config::NodePolicy> {
        fc::read_policy(path, service_uid()?)
            .map_err(anyhow::Error::msg)
            .context("Firecracker node policy")
    };
    match command {
        Command::Enroll {
            instance,
            unit,
            cgroup,
            user,
            kilnd,
            policy,
        } => {
            let instance = kilnd::model::Id128::parse(instance)
                .map_err(|_| anyhow::anyhow!("--instance must be a 32-digit hexadecimal ID"))?;
            if !kilnd.is_absolute() {
                bail!("--kilnd must be absolute");
            }
            fc::enroll_instance(
                &policy_at(policy)?,
                instance,
                unit,
                cgroup.as_deref(),
                account(user).with_context(|| format!("--user {user}"))?,
                // SAFETY: geteuid has no preconditions.
                unsafe { libc::geteuid() },
                kilnd,
            )
            .map_err(anyhow::Error::msg)
            .context("enroll instance")
        }
        Command::Enrollments { policy } => {
            let rows = fc::list_enrollments(&policy_at(policy)?)
                .map_err(anyhow::Error::msg)
                .context("read enrollments")?;
            Ok(serde_json::to_string(&rows)?)
        }
        Command::RefreshEnrollments {
            kilnd,
            check,
            policy,
        } => {
            if !kilnd.is_absolute() {
                bail!("--kilnd must be absolute");
            }
            fc::refresh_enrollments(&policy_at(policy)?, kilnd, *check)
                .map_err(anyhow::Error::msg)
                .context("refresh enrollments")
        }
        Command::OfflineInventory {
            daemon_db,
            report,
            policy,
        } => {
            let mut databases = std::collections::BTreeMap::new();
            for entry in daemon_db {
                let (instance, path) = entry
                    .split_once('=')
                    .context("--daemon-db takes <instance>=<path>")?;
                let instance = kilnd::model::Id128::parse(instance)
                    .map_err(|_| anyhow::anyhow!("--daemon-db: a 32-digit instance ID"))?;
                if databases.insert(instance, PathBuf::from(path)).is_some() {
                    bail!("--daemon-db names {instance} twice");
                }
            }
            fc::offline_inventory(&policy_at(policy)?, &databases, report)
                .map_err(anyhow::Error::msg)
                .context("offline inventory")
        }
        Command::ClearNodeFaults { report, policy } => {
            fc::clear_node_faults(&policy_at(policy)?, report)
                .map_err(anyhow::Error::msg)
                .context("clear node faults")
        }
        Command::CreateTimings {
            allocation,
            last,
            summary,
        } => {
            let select = match allocation {
                Some(id) => {
                    fc::timing::Select::Allocation(kilnd::model::Id128::parse(id).map_err(
                        |_| anyhow::anyhow!("--allocation must be a 32-digit hexadecimal ID"),
                    )?)
                }
                None => fc::timing::Select::Last(*last),
            };
            fc::timing::report(std::io::stdin().lock(), select, *summary)
                .context("read the helper's log")
        }
        Command::LedgerStats { policy } => fc::ledger_stats(&policy_at(policy)?)
            .map_err(anyhow::Error::msg)
            .context("ledger statistics"),
        Command::RestoreEnrollments { snapshot, policy } => {
            let file = std::fs::File::open(snapshot).context("open the snapshot")?;
            let mut text = Vec::new();
            file.take(MAX_SNAPSHOT_BYTES + 1)
                .read_to_end(&mut text)
                .context("read the snapshot")?;
            if text.len() as u64 > MAX_SNAPSHOT_BYTES {
                bail!("the snapshot is too large");
            }
            let rows: Vec<fc::peer::Enrollment> =
                serde_json::from_slice(&text).context("parse the snapshot")?;
            fc::restore_enrollments(&policy_at(policy)?, &rows)
                .map_err(anyhow::Error::msg)
                .context("restore enrollments")
        }
    }
}

/// The numeric service UID comes only from the root-controlled account database.
fn service_uid() -> Result<u32> {
    let (uid, _) = account("kilnd").context("missing kilnd system account")?;
    if uid == 0 {
        bail!("missing non-root kilnd system account");
    }
    Ok(uid)
}

/// A named account's UID and primary GID, from that same database.
fn account(name: &str) -> Result<(u32, u32)> {
    let name = CString::new(name).context("account name")?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut data = vec![0; 16384];
    let mut found = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            data.as_mut_ptr(),
            data.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        bail!("no such account");
    }
    Ok((pwd.pw_uid, pwd.pw_gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backlog B4 (row 12): one startup line for each way the checkpoint group comes up,
    /// written once through the writer startup is given (the B4 break-it's HIGH 1: the
    /// line itself, not only its text, is what the test watches).
    #[test]
    fn the_checkpoint_group_logs_one_line_for_each_startup_state() {
        // Each outcome, the group it returns, and every byte its writer received.
        let start = |enabled: bool, built: std::result::Result<u8, &str>| {
            let mut out = Vec::new();
            let mut calls = 0;
            let node = start_checkpoint_group(
                enabled,
                || {
                    calls += 1;
                    built
                },
                &mut out,
            );
            (node.unwrap(), calls, String::from_utf8(out).unwrap())
        };
        assert_eq!(
            start(true, Ok(7)),
            (Some(7), 1, "kilnd-helper: checkpoint group: enabled\n".into())
        );
        // Without the flag the group is never built, and the line still comes.
        assert_eq!(
            start(false, Ok(7)),
            (None, 0, "kilnd-helper: checkpoint group: off (flag)\n".into())
        );
        assert_eq!(
            start(true, Err("no checkpoint session")),
            (
                None,
                1,
                "kilnd-helper: checkpoint group: failed: no checkpoint session\n".into()
            )
        );
    }

    /// A standard error that rejects every write, keeping what it was offered.
    #[derive(Default)]
    struct FailingWriter {
        offered: Vec<u8>,
    }

    impl std::io::Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.offered.extend_from_slice(bytes);
            Err(std::io::Error::other("stderr unavailable"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Backlog B4 fix round 2 (the recheck's HIGH 1): the eprintln! the startup line
    /// replaced panicked when standard error rejected it, so the helper never served. Now
    /// a rejected line fails startup in every outcome: the error comes back, `serve` never
    /// runs, and a group that was built is dropped unused.
    #[tokio::test]
    async fn a_rejected_checkpoint_startup_line_fails_startup_in_every_outcome() {
        let node = std::sync::Arc::new(7u8);
        for (enabled, built, line, calls_wanted) in [
            (true, Ok(()), "kilnd-helper: checkpoint group: enabled", 1),
            (false, Ok(()), "kilnd-helper: checkpoint group: off (flag)", 0),
            (
                true,
                Err("no checkpoint session"),
                "kilnd-helper: checkpoint group: failed: no checkpoint session",
                1,
            ),
        ] {
            let mut out = FailingWriter::default();
            let mut calls = 0;
            let mut served = false;
            let started = serve_after_checkpoint_line(
                enabled,
                || {
                    calls += 1;
                    built.map(|()| node.clone())
                },
                &mut out,
                |_| {
                    served = true;
                    async {}
                },
            )
            .await;
            let error = started.expect_err(line);
            assert_eq!(error.to_string(), "stderr unavailable", "{line}");
            assert!(!served, "{line}: served after its startup line was rejected");
            assert_eq!(calls, calls_wanted, "{line}");
            // The line was offered (the writer refused it before its newline): the
            // write failed, not a skipped line.
            assert_eq!(String::from_utf8(out.offered).unwrap(), line);
            // Nothing built survives the failed call.
            assert_eq!(std::sync::Arc::strong_count(&node), 1, "{line}");
        }
        // With the line written, serve runs once, with the group the outcome built.
        for (enabled, built, wanted) in [
            (true, Ok(7u8), Some(7)),
            (false, Ok(7), None),
            (true, Err("no checkpoint session"), None),
        ] {
            let mut out = Vec::new();
            let mut served = Vec::new();
            serve_after_checkpoint_line(enabled, || built, &mut out, |group| {
                served.push(group);
                async {}
            })
            .await
            .unwrap();
            assert_eq!(served, [wanted]);
            assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        }
    }

    /// The recheck's own case: construction fails and standard error rejects the line
    /// too. The helper used to panic here; startup must still fail, not carry on.
    #[test]
    fn a_checkpoint_startup_line_write_failure_keeps_the_old_exit_behavior() {
        let mut out = FailingWriter::default();
        assert!(
            start_checkpoint_group::<u8, &str>(
                true,
                || Err("checkpoint construction failed"),
                &mut out,
            )
            .is_err()
        );
    }

    /// The startup line `serve_groups` writes for each checkpoint flag.
    const LINES: [(bool, &str); 2] = [
        (false, "kilnd-helper: checkpoint group: off (flag)\n"),
        (true, "kilnd-helper: checkpoint group: enabled\n"),
    ];

    /// What production's `serve` hands `serve_groups`, under a fresh directory: a bound,
    /// nonblocking Unix listener, and a kiln path that exists nowhere and is this test's
    /// alone. The directory lives as long as the setup.
    struct Setup {
        _dir: tempfile::TempDir,
        socket: PathBuf,
        kiln: PathBuf,
        listener: std::os::unix::net::UnixListener,
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let kiln = dir.path().join("no-kiln-here");
        Setup {
            _dir: dir,
            socket,
            kiln,
            listener,
        }
    }

    /// Production's orchestration after the socket checks, as `serve` runs it, with no
    /// Firecracker group and this test's own user as the service account.
    async fn serve_groups_as_production(
        listener: std::os::unix::net::UnixListener,
        kiln: PathBuf,
        enable_checkpoints: bool,
        out: &mut impl std::io::Write,
    ) -> Result<()> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        serve_groups(listener, uid, kiln, None, enable_checkpoints, out).await
    }

    fn monotonic_ns() -> u64 {
        let mut time: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: `time` is a valid timespec to write.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
            0
        );
        time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
    }

    /// The smallest request the helper answers without root or a kiln: the installed
    /// CLI's capabilities, as kilnd's client sends it (an empty descriptor envelope, then
    /// one length-prefixed frame).
    fn capabilities_request() -> Vec<u8> {
        let frame = format!(
            r#"{{"version":3,"timeout_ms":5000,"deadline_ns":{},"operation":{{"kiln":{{"capabilities":{{"id":null}}}}}}}}"#,
            monotonic_ns() + 5_000_000_000
        );
        let mut bytes = vec![0x4b];
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(frame.as_bytes());
        bytes
    }

    /// Everything the helper sends back for [`capabilities_request`] when `kiln` doesn't
    /// exist: its empty descriptor envelope, one frame, then EOF. The frame names `kiln`,
    /// so only the runtime `serve_with_groups` builds from this test's own path answers it.
    fn capabilities_reply(kiln: &std::path::Path) -> Vec<u8> {
        let error = format!(
            "{} requires persistent-exec protocol v1, scoped gc ID... and persistent-create \
             certainty (feature 0x10): No such file or directory (os error 2)",
            kiln.display()
        );
        let frame = format!(
            r#"{{"error":{{"error":{{"incompatible":{}}},"definitely_not_created":false}}}}"#,
            serde_json::to_string(&error).unwrap()
        );
        let mut bytes = vec![0x4b];
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(frame.as_bytes());
        bytes
    }

    /// One client's whole exchange: connect, send [`capabilities_request`], keep its own
    /// side open (an EOF would cancel the request) and read until the helper's EOF.
    async fn ask(socket: &std::path::Path) -> std::io::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        stream.write_all(&capabilities_request()).await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        Ok(reply)
    }

    /// Requires `serve_groups` with `out` to serve `setup`'s own listener: while it is
    /// still running, a client's request on that socket gets the exact reply only the
    /// helper's runtime gives, within the bound.
    async fn assert_serves(setup: Setup, enable: bool, out: &mut impl std::io::Write, case: &str) {
        let Setup {
            _dir,
            socket,
            kiln,
            listener,
        } = setup;
        let serving = serve_groups_as_production(listener, kiln.clone(), enable, out);
        tokio::pin!(serving);
        let reply = tokio::select! {
            returned = &mut serving => panic!("{case}: stopped serving: {returned:?}"),
            reply = tokio::time::timeout(std::time::Duration::from_secs(10), ask(&socket)) => reply,
        };
        let reply = reply
            .unwrap_or_else(|_| panic!("{case}: no answer within 10 s"))
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert!(
            reply == capabilities_reply(&kiln),
            "{case}: answered {:?}",
            String::from_utf8_lossy(&reply)
        );
    }

    /// Requires `serve_groups` with `out` to fail with `error` and serve nothing. A
    /// client is already connected with its request when it starts, so a helper that
    /// served anything, on this listener or a copy of it, would have answered it; then
    /// the socket refuses the next client.
    async fn assert_refuses(
        setup: Setup,
        enable: bool,
        out: &mut impl std::io::Write,
        case: &str,
        error: &str,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Setup {
            _dir,
            socket,
            kiln,
            listener,
        } = setup;
        let waiting = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        waiting.set_nonblocking(true).unwrap();
        let mut waiting = tokio::net::UnixStream::from_std(waiting).unwrap();
        waiting.write_all(&capabilities_request()).await.unwrap();
        let returned = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve_groups_as_production(listener, kiln, enable, out),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: still serving after a failed startup line"));
        let failed = returned.expect_err(case);
        assert_eq!(
            format!("{failed:#}"),
            format!("write the checkpoint group's startup line to standard error: {error}"),
            "{case}"
        );
        // The waiting client's connection ends with not one byte of an answer.
        let mut answer = Vec::new();
        let ended = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            waiting.read_to_end(&mut answer),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: the waiting client's connection stayed open"));
        if let Err(e) = ended {
            assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{case}: {e}");
        }
        assert!(
            answer.is_empty(),
            "{case}: answered {:?}",
            String::from_utf8_lossy(&answer)
        );
        let refused = std::os::unix::net::UnixStream::connect(&socket)
            .expect_err("nothing may accept on the helper's socket");
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "{case}"
        );
    }

    /// A standard error that rejects every write and every flush.
    struct RejectingWriter;

    impl std::io::Write for RejectingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("stderr unavailable"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("stderr unavailable"))
        }
    }

    /// Backlog B4 fix round 3 (recheck 2's HIGH 1): the production orchestration itself,
    /// not only the helper inside it, refuses to serve when its startup line is rejected.
    #[tokio::test]
    async fn the_helper_does_not_serve_when_its_startup_line_is_rejected() {
        for (enable, _) in LINES {
            let case = format!("checkpoints {enable}, every write rejected");
            assert_refuses(
                setup(),
                enable,
                &mut RejectingWriter,
                &case,
                "stderr unavailable",
            )
            .await;
        }
    }

    /// The control for the test above (fix round 4, recheck 3's HIGH 1): with a working
    /// standard error the same orchestration answers a request on the listener it was
    /// given, having written its one line.
    #[tokio::test]
    async fn the_helper_serves_once_its_startup_line_is_written() {
        for (enable, line) in LINES {
            let mut out = Vec::new();
            assert_serves(setup(), enable, &mut out, &format!("checkpoints {enable}")).await;
            assert_eq!(String::from_utf8(out).unwrap(), line);
        }
    }

    /// What a scripted standard error does to the write that reaches its offset.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Shape {
        /// That write and every later one fail.
        Error,
        /// That write takes nothing, `Ok(0)`, which `write_all` reports as WriteZero.
        Zero,
        /// That write is interrupted once, which `write_all` retries; then it takes all.
        Interrupted,
    }

    /// A standard error that takes at most `chunk` bytes per write, and shapes the first
    /// write that arrives once it holds `at` bytes. It keeps every byte it took.
    struct ScriptedWriter {
        shape: Shape,
        at: usize,
        chunk: usize,
        taken: Vec<u8>,
        interrupted: bool,
    }

    impl std::io::Write for ScriptedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.taken.len() == self.at && !bytes.is_empty() {
                match self.shape {
                    Shape::Error => return Err(std::io::Error::other("stderr unavailable")),
                    Shape::Zero => return Ok(0),
                    Shape::Interrupted if !self.interrupted => {
                        self.interrupted = true;
                        return Err(std::io::ErrorKind::Interrupted.into());
                    }
                    Shape::Interrupted => {}
                }
            }
            // Short of the offset, never past it, so the shaped write lands exactly there.
            let room = if self.interrupted {
                usize::MAX
            } else {
                self.at - self.taken.len()
            };
            let took = bytes.len().min(self.chunk).min(room);
            self.taken.extend_from_slice(&bytes[..took]);
            Ok(took)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Every way the scripted writer can take a line: one byte per write, a few, or all
    /// it is offered.
    const CHUNKS: [usize; 3] = [1, 3, usize::MAX];

    /// Fix round 4 (recheck 3's HIGH 2): a startup line that fails at any byte, after
    /// any number of short writes, fails startup with that error, the writer holds
    /// exactly the line's first bytes, and nothing is served, in both checkpoint states.
    #[tokio::test]
    async fn a_startup_line_that_fails_at_any_byte_is_never_served() {
        for (enable, line) in LINES {
            for chunk in CHUNKS {
                for at in 0..line.len() {
                    for (shape, error) in [
                        (Shape::Error, "stderr unavailable"),
                        (Shape::Zero, "failed to write whole buffer"),
                    ] {
                        let case = format!(
                            "checkpoints {enable}, {shape:?} at byte {at} of {}, \
                             writes of at most {chunk}",
                            line.len()
                        );
                        let mut out = ScriptedWriter {
                            shape,
                            at,
                            chunk,
                            taken: Vec::new(),
                            interrupted: false,
                        };
                        assert_refuses(setup(), enable, &mut out, &case, error).await;
                        assert_eq!(out.taken, line.as_bytes()[..at], "{case}");
                    }
                }
            }
        }
    }

    /// The other side of the test above: a line taken whole, in any number of short
    /// writes, or after an interrupted write at any byte, is served.
    #[tokio::test]
    async fn a_startup_line_taken_whole_is_served_however_it_was_written() {
        for (enable, line) in LINES {
            for chunk in CHUNKS {
                let mut cases: Vec<(Shape, usize)> =
                    (0..line.len()).map(|at| (Shape::Interrupted, at)).collect();
                // A writer that would fail only after the whole line never fails it.
                cases.extend([(Shape::Error, line.len()), (Shape::Zero, line.len())]);
                for (shape, at) in cases {
                    let case = format!(
                        "checkpoints {enable}, {shape:?} at byte {at} of {}, \
                         writes of at most {chunk}",
                        line.len()
                    );
                    let mut out = ScriptedWriter {
                        shape,
                        at,
                        chunk,
                        taken: Vec::new(),
                        interrupted: false,
                    };
                    assert_serves(setup(), enable, &mut out, &case).await;
                    assert_eq!(out.taken, line.as_bytes(), "{case}");
                    assert_eq!(out.interrupted, shape == Shape::Interrupted, "{case}");
                }
            }
        }
    }

    /// Fix round 4 (recheck 3's MEDIUM): production's `serve` can't be run here (it needs
    /// root, the `kilnd` account and systemd's socket), so its wiring is held by the
    /// source itself. `serve` is exactly its three steps and one `serve_groups` call with
    /// standard error, and outside the tests nothing but `serve_groups` names a serving
    /// entry point, converts a listener or copies one. A text check: it can't see through
    /// a macro or another crate's function that serves.
    #[test]
    fn serve_is_only_its_steps() {
        let source = include_str!("kilnd-helper.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let start = production
            .find("async fn serve(args: &Args, bin: PathBuf) -> Result<()> {")
            .unwrap();
        let end = start + production[start..].find("\n}\n").unwrap();
        assert_eq!(
            words(&production[start..end]),
            words(
                "async fn serve(args: &Args, bin: PathBuf) -> Result<()> {
                    let listener = systemd_listener()?;
                    let service_uid = service_uid()?;
                    let firecracker = start_firecracker(args, service_uid).await;
                    serve_groups(
                        listener,
                        service_uid,
                        bin,
                        firecracker,
                        args.enable_checkpoints,
                        &mut std::io::stderr(),
                    )
                    .await"
            )
        );
        // Code only: comments may name what they like.
        let code = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for (name, count) in [
            ("serve_groups(", 2),
            ("serve_with_groups", 1),
            ("serve_with_firecracker", 0),
            ("helper::serve(", 0),
            ("serve_accepting", 0),
            ("from_std", 1),
            ("from_raw_fd(", 1),
            ("try_clone", 0),
            ("spawn(", 1),
        ] {
            assert_eq!(code.matches(name).count(), count, "{name}");
        }
    }
}
