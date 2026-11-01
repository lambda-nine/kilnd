//! `kilnd check-attachment`: the enrollment proof, from a real process in whatever unit,
//! account and image it runs. It only attaches. Nothing here selects a backend to serve.
use crate::runtime::firecracker::FirecrackerRuntime;
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};

/// Prints what attached. With `hold`, stays attached, holding the state lock, until SIGTERM
/// or SIGINT, as a daemon would.
pub async fn run(state_dir: &Path, helper_socket: PathBuf, hold: bool) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        bail!("kilnd refuses root; run this as the instance's own account");
    }
    let store = Store::open(state_dir)?;
    let identity = store.identity()?;
    let runtime =
        FirecrackerRuntime::new(helper_socket, identity.instance_id, identity.database_uuid);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let node = runtime
        .prove_attachment(deadline)
        .await
        .map_err(|error| anyhow::anyhow!("attach {}: {error}", identity.instance_id))?;
    println!("attached {} on node {node}", identity.instance_id);
    if hold {
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
    }
    Ok(())
}
