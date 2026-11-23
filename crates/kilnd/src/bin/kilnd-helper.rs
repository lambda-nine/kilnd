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
/// groups, the serve, and the groups' shutdown.
async fn serve(args: &Args, bin: PathBuf) -> Result<()> {
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
    let service_uid = service_uid()?;
    // Firecracker's startup failure never takes legacy kiln down with it: the group
    // answers Disabled, and a configured node with a bad ledger answers Unavailable.
    let firecracker = match &args.firecracker_policy {
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
    };
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

    /// A listener as production's `serve` hands it on: a bound Unix socket, nonblocking,
    /// under a fresh directory. The directory lives as long as the listener is used.
    fn production_listener() -> (
        tempfile::TempDir,
        PathBuf,
        std::os::unix::net::UnixListener,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        (dir, path, listener)
    }

    /// Production's orchestration after the socket checks, as `serve` runs it, with no
    /// Firecracker group. A real kiln is never reached: nothing here sends a request.
    async fn run_serve_groups(
        listener: std::os::unix::net::UnixListener,
        enable_checkpoints: bool,
        out: &mut impl std::io::Write,
        within: std::time::Duration,
    ) -> std::result::Result<Result<()>, tokio::time::error::Elapsed> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let bin = PathBuf::from("/nonexistent/kiln");
        tokio::time::timeout(
            within,
            serve_groups(listener, uid, bin, None, enable_checkpoints, out),
        )
        .await
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
    /// A helper that started serving never returns, so returning at all, and with the
    /// write's error, is the proof; the socket then has no one accepting on it.
    #[tokio::test]
    async fn the_helper_does_not_serve_when_its_startup_line_is_rejected() {
        for enable_checkpoints in [false, true] {
            let (_dir, path, listener) = production_listener();
            let returned = run_serve_groups(
                listener,
                enable_checkpoints,
                &mut RejectingWriter,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("checkpoints {enable_checkpoints}: still serving after a rejected line")
            });
            let error = returned.expect_err("a rejected startup line must fail startup");
            assert_eq!(
                format!("{error:#}"),
                "write the checkpoint group's startup line to standard error: \
                 stderr unavailable",
                "checkpoints {enable_checkpoints}"
            );
            // The listener is gone with the call: a client finds no helper.
            let refused = std::os::unix::net::UnixStream::connect(&path)
                .expect_err("nothing may accept on the helper's socket");
            assert_eq!(
                refused.kind(),
                std::io::ErrorKind::ConnectionRefused,
                "checkpoints {enable_checkpoints}"
            );
        }
    }

    /// The control for the test above: the same orchestration with a working standard
    /// error is still serving when a short timeout runs out, having written its one line,
    /// so the timeout tells serving from not serving.
    #[tokio::test]
    async fn the_helper_serves_once_its_startup_line_is_written() {
        for (enable_checkpoints, line) in [
            (false, "kilnd-helper: checkpoint group: off (flag)\n"),
            (true, "kilnd-helper: checkpoint group: enabled\n"),
        ] {
            let (_dir, path, listener) = production_listener();
            let mut out = Vec::new();
            let serving = async {
                run_serve_groups(
                    listener,
                    enable_checkpoints,
                    &mut out,
                    std::time::Duration::from_millis(300),
                )
                .await
            };
            // A client reaches a live listener while it serves.
            let connect = async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                tokio::net::UnixStream::connect(&path).await
            };
            let (served, connected) = tokio::join!(serving, connect);
            assert!(
                served.is_err(),
                "checkpoints {enable_checkpoints}: stopped serving: {served:?}"
            );
            connected.unwrap_or_else(|e| panic!("checkpoints {enable_checkpoints}: {e}"));
            assert_eq!(String::from_utf8(out).unwrap(), line);
        }
    }
}
