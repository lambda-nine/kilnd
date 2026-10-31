//! Socket-activated root privilege boundary. No gRPC, DB, shell, or arbitrary argv.
use anyhow::{Context, Result, bail};
use clap::Parser;
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
                let config = kilnd::helper::firecracker::production_config(policy);
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
    let name = CString::new("kilnd").unwrap();
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
    if rc != 0 || found.is_null() || pwd.pw_uid == 0 {
        bail!("missing non-root kilnd system account");
    }
    Ok(pwd.pw_uid)
}
