//! Socket-activated root privilege boundary. No gRPC, DB, shell, or arbitrary argv.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Root-only: names the Unix account, systemd unit and installed kilnd image allowed to
    /// serve an instance. Stop kilnd-helper first: this takes its node lock, and runs over
    /// no socket.
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
        /// The installed kilnd image that unit runs. Enroll again after replacing it.
        #[arg(long, default_value = kilnd::helper::firecracker::peer::DEFAULT_KILND_PATH)]
        kilnd: PathBuf,
        /// The root-owned Firecracker node policy naming the ledger and the enrollment limit.
        #[arg(long, default_value = "/etc/kilnd/firecracker-node.json")]
        policy: PathBuf,
    },
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if unsafe { libc::geteuid() } != 0 {
        bail!("kilnd-helper must run as root");
    }
    unsafe {
        libc::umask(0o077);
    }
    if let Some(Command::Enroll {
        instance,
        unit,
        cgroup,
        user,
        kilnd,
        policy,
    }) = &args.command
    {
        let instance = kilnd::model::Id128::parse(instance)
            .map_err(|_| anyhow::anyhow!("--instance must be a 32-digit hexadecimal ID"))?;
        if !kilnd.is_absolute() {
            bail!("--kilnd must be absolute");
        }
        let policy = kilnd::helper::firecracker::read_policy(policy, service_uid()?)
            .map_err(anyhow::Error::msg)
            .context("Firecracker node policy")?;
        let done = kilnd::helper::firecracker::enroll_instance(
            &policy,
            instance,
            unit,
            cgroup.as_deref(),
            account(user).with_context(|| format!("--user {user}"))?,
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() },
            kilnd,
        )
        .map_err(anyhow::Error::msg)
        .context("enroll instance")?;
        println!("{done}");
        return Ok(());
    }
    // No request can select an executable; the administrator's configured
    // executable and every ancestor must be root-owned and not writable.
    if !args.kiln.is_absolute() {
        bail!("kiln path must be absolute");
    }
    let bin = args.kiln.canonicalize()?;
    for path in bin.ancestors() {
        let m = std::fs::symlink_metadata(path)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!("untrusted executable path {}", path.display());
        }
    }
    if !bin.is_file() {
        bail!("kiln executable is not a file");
    }
    if args.firecracker_init_ledger {
        let path = args.firecracker_policy.as_deref().context("policy path")?;
        let policy = kilnd::helper::firecracker::read_policy(path, service_uid()?)
            .map_err(anyhow::Error::msg)
            .context("Firecracker node policy")?;
        return kilnd::helper::firecracker::provision_ledger(&policy)
            .map_err(anyhow::Error::msg)
            .context("provision node ledger");
    }
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
    let stop = CancellationToken::new();
    let stopped = stop.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        stopped.cancel();
    });
    let served = kilnd::helper::serve_with_firecracker(
        tokio::net::UnixListener::from_std(listener)?,
        service_uid,
        bin,
        firecracker.clone(),
        stop,
    )
    .await;
    if let Some(node) = firecracker {
        node.shutdown();
    }
    served.context("root helper")
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
