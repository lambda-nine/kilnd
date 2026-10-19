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
/// cancels running executions, waits briefly for their replies, and drains
/// accepted manager-owned operations even if their RPCs disconnected.
pub async fn serve<R: Runtime>(
    manager: Arc<Manager<R>>,
    listener: UnixListener,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) -> Result<()> {
    serve_with_final_wait(manager, listener, shutdown, grace, FINAL_WAIT).await
}

async fn serve_with_final_wait<R: Runtime>(
    manager: Arc<Manager<R>>,
    listener: UnixListener,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
    final_wait: Duration,
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

    let mut server_result = tokio::select! {
        r = &mut server => Some(r),
        () = &mut shutdown => None,
    };
    let requested = server_result.is_none();
    info!(grace_secs = grace.as_secs(), "shutting down: refusing new work, waiting for requests and owned operations");
    manager.begin_shutdown();
    if requested {
        stop.cancel();
    }
    let operations = manager.drain_operations();
    tokio::pin!(operations);
    let mut operations_done = false;
    let grace_deadline = tokio::time::sleep(grace);
    tokio::pin!(grace_deadline);

    // Transport completion does not own manager operations. Keep the grace
    // clock running until both have finished, and never repoll either future
    // after completion.
    while server_result.is_none() || !operations_done {
        tokio::select! {
            result = &mut server, if server_result.is_none() => server_result = Some(result),
            () = &mut operations, if !operations_done => operations_done = true,
            () = &mut grace_deadline => break,
        }
    }
    if operations_done && let Some(result) = server_result.take() {
        return result.context("serve");
    }

    warn!("grace period over; canceling running executions");
    manager.cancel_executions();
    let final_deadline = tokio::time::sleep(final_wait);
    tokio::pin!(final_deadline);
    while server_result.is_none() || !operations_done {
        tokio::select! {
            result = &mut server, if server_result.is_none() => server_result = Some(result),
            () = &mut operations, if !operations_done => operations_done = true,
            () = &mut final_deadline => {
                warn!("requests still in flight; continuing to drain accepted manager operations before exit");
                break;
            }
        }
    }
    if !operations_done {
        operations.await;
    }
    match server_result {
        Some(result) => result.context("serve"),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{CreateRequest, ExecRequest, Limits};
    use crate::model::{ExecutionState, SandboxState};
    use crate::runtime::fake::{FakeGate, FakeRuntime};
    use crate::store::Store;

    #[tokio::test]
    async fn shutdown_drains_detached_compensation_beyond_final_rpc_wait() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("kilnd.sock");
        let fake = FakeRuntime::default();
        let remove_gate = FakeGate::default();
        fake.state().remove_before_delete = Some(remove_gate.clone());
        let store = Store::open_in_memory().unwrap();
        store.reject_ready_updates().unwrap();
        let manager = Arc::new(Manager::new(fake.clone(), store, Limits::default()));

        let waiter = tokio::spawn({
            let manager = manager.clone();
            async move { manager.create(CreateRequest::default()).await }
        });
        remove_gate.entered().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(manager.list(true).unwrap()[0].state, SandboxState::Deleting);

        // No transport connection exists. The shortened transport deadlines
        // expire, but the server must remain alive for manager-owned cleanup.
        let listener = bind(&socket, None).unwrap();
        let mut server = tokio::spawn(serve_with_final_wait(
            manager.clone(),
            listener,
            async {},
            Duration::ZERO,
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server).await.is_err(),
            "server exited at its final RPC deadline while compensation was paused"
        );

        remove_gate.release();
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
        let row = manager.list(true).unwrap().remove(0);
        assert_eq!(row.state, SandboxState::Failed);
        assert!(row.failure_reason.as_deref().unwrap().contains("backend removed"));
        assert!(fake.state().sandboxes.is_empty());
    }

    #[tokio::test]
    async fn shutdown_without_transport_honors_grace_and_drains_exec_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("kilnd.sock");
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
        let sandbox = manager.create(CreateRequest::default()).await.unwrap();
        let gate = FakeGate::default();
        fake.state().exec_before_run = Some(gate.clone());
        let waiter = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .exec(ExecRequest {
                        sandbox_id: sandbox.id,
                        argv: vec!["sleep".into()],
                        stdin: vec![],
                        timeout_ms: 0,
                    })
                    .await
            }
        });
        gate.entered().await;

        // There is no transport connection to keep tonic alive. The grace
        // deadline must still request shutdown cancellation, while owned exec
        // cleanup keeps the server alive beyond the final reply deadline.
        let listener = bind(&socket, None).unwrap();
        let mut server = tokio::spawn(serve_with_final_wait(
            manager.clone(),
            listener,
            async {},
            Duration::from_millis(20),
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server).await.is_err(),
            "server exited while canceled exec cleanup was paused"
        );
        assert_eq!(manager.health().await.unwrap().running_executions, 1);

        gate.release();
        let execution = tokio::time::timeout(Duration::from_secs(5), waiter).await.unwrap().unwrap().unwrap();
        assert_eq!(execution.state, ExecutionState::Canceled);
        assert_eq!(execution.failure_reason.as_deref(), Some("kilnd shut down"));
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
        assert_eq!(fake.state().active_execs, 0);
    }
}
