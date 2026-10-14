//! The Unix socket and the server's lifecycle: bind with tight permissions,
//! serve, and shut down gracefully.

use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kilnd_api::v1::kilnd_service_server::KilndServiceServer;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::manager::Manager;
use crate::runtime::Runtime;
use crate::service::Service;

/// How long to wait for in-flight requests after running executions were
/// canceled, before exiting regardless.
const FINAL_WAIT: Duration = Duration::from_secs(10);

/// Binds the API socket. Its directory and the socket belong to the daemon's
/// user; with `gid`, that group may connect too (directory 0750, socket
/// 0660), otherwise only the owner (0700 and 0600). A stale socket is
/// replaced; anything else at the path is an error.
pub fn bind(path: &Path, gid: Option<u32>) -> Result<UnixListener> {
    let dir = path.parent().context("socket path has no directory")?;
    let (dir_mode, sock_mode) = if gid.is_some() { (0o750, 0o660) } else { (0o700, 0o600) };
    if !dir.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid {
        bail!("{} must be a directory owned by uid {euid}", dir.display());
    }
    chown(dir, None, gid).with_context(|| format!("chown {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode))?;

    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    chown(path, None, gid).with_context(|| format!("chown {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(sock_mode))?;
    Ok(listener)
}

/// Serves until `shutdown` resolves, then: refuses new work and stops
/// accepting connections, lets in-flight requests finish for `grace`,
/// cancels running executions, and waits briefly for their replies.
pub async fn serve<R: Runtime>(
    manager: Arc<Manager<R>>,
    listener: UnixListener,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) -> Result<()> {
    let incoming = UnixListenerStream::new(listener).map(|conn| {
        match &conn {
            Ok(stream) => match stream.peer_cred() {
                Ok(c) => info!(uid = c.uid(), gid = c.gid(), pid = c.pid().unwrap_or(0), "client connected"),
                Err(e) => warn!(error = %e, "client connected; peer credentials unavailable"),
            },
            Err(e) => warn!(error = %e, "accept failed"),
        }
        conn
    });
    let stop = CancellationToken::new();
    let server = tonic::transport::Server::builder()
        .add_service(KilndServiceServer::new(Service::new(manager.clone())))
        .serve_with_incoming_shutdown(incoming, stop.clone().cancelled_owned());
    tokio::pin!(server);
    tokio::pin!(shutdown);

    tokio::select! {
        r = &mut server => return r.context("serve"),
        () = &mut shutdown => {}
    }
    info!(grace_secs = grace.as_secs(), "shutting down: refusing new work, waiting for requests in flight");
    manager.begin_shutdown();
    stop.cancel();
    tokio::select! {
        r = &mut server => return r.context("serve"),
        () = tokio::time::sleep(grace) => {}
    }
    warn!("grace period over; canceling running executions");
    manager.cancel_executions();
    tokio::select! {
        r = &mut server => r.context("serve"),
        () = tokio::time::sleep(FINAL_WAIT) => {
            warn!("requests still in flight; exiting anyway");
            Ok(())
        }
    }
}
