//! The Unix socket and the server's lifecycle: bind with tight permissions,
//! serve, and shut down gracefully.

use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kilnd_api::v1::kilnd_service_server::KilndServiceServer;
use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::lock::ExclusiveFileLock;
use crate::manager::Manager;
use crate::runtime::Runtime;
use crate::service::Service;

/// How long to wait for in-flight requests after running executions were
/// canceled, before exiting regardless.
const FINAL_WAIT: Duration = Duration::from_secs(10);
const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self { device: meta.dev(), inode: meta.ino() }
    }

    fn matches(self, meta: &std::fs::Metadata) -> bool {
        self.device == meta.dev() && self.inode == meta.ino()
    }
}

/// A listener plus exclusive ownership of its directory and pathname.
/// Cleanup is conditional on the pathname still identifying this instance's
/// socket, so a replacement is never unlinked on shutdown.
pub struct BoundSocket {
    listener: UnixListener,
    path_guard: SocketPathGuard,
}

struct SocketPathGuard {
    path: PathBuf,
    identity: FileIdentity,
    active: bool,
    _directory_lock: ExclusiveFileLock,
}

impl SocketPathGuard {
    fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.file_type().is_socket() && self.identity.matches(&meta) => {
                std::fs::remove_file(&self.path).with_context(|| format!("remove owned socket {}", self.path.display()))?;
            }
            Ok(_) => {
                warn!(socket = %self.path.display(), "socket path was replaced; leaving replacement untouched");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("inspect owned socket {}", self.path.display())),
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            warn!(error = %format!("{e:#}"), socket = %self.path.display(), "could not clean up owned socket");
        }
    }
}

/// Binds the API socket. Its directory and the socket belong to the daemon's
/// user; with `gid`, that group may connect too (directory 0750, socket
/// 0660), otherwise only the owner (0700 and 0600). Its directory is locked
/// for the listener's lifetime. On Linux, a socket is replaced only after a
/// bounded connection probe proves it stale; platforms where refusal can
/// also mean backlog pressure fail closed. Anything else is an error.
pub async fn bind(path: &Path, gid: Option<u32>) -> Result<BoundSocket> {
    let dir = path.parent().context("socket path has no directory")?;
    let (dir_mode, sock_mode) = if gid.is_some() { (0o750, 0o660) } else { (0o700, 0o600) };
    if !dir.exists() {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
        }
    }
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != euid {
        bail!("{} must be owned by uid {euid}, found uid {}", dir.display(), meta.uid());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        bail!(
            "{} is writable by group or others (mode {:o})",
            dir.display(),
            meta.permissions().mode() & 0o777
        );
    }

    let directory_lock = ExclusiveFileLock::acquire(&dir.join(".kilnd.socket.lock"), "socket directory")?;
    remove_stale_socket(path).await?;

    // A losing invocation must not alter an incumbent directory's access.
    // Permission changes occur only after this process owns the directory
    // lock and has ruled out a live listener.
    chown(dir, None, gid).with_context(|| format!("chown {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode))?;

    let listener = std::os::unix::net::UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    let socket_meta = std::fs::symlink_metadata(path).with_context(|| format!("inspect bound socket {}", path.display()))?;
    if !socket_meta.file_type().is_socket() {
        bail!("{} did not become a socket after bind", path.display());
    }
    let path_guard = SocketPathGuard {
        path: path.to_path_buf(),
        identity: FileIdentity::of(&socket_meta),
        active: true,
        _directory_lock: directory_lock,
    };
    chown(path, None, gid).with_context(|| format!("chown {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(sock_mode))?;
    listener.set_nonblocking(true).with_context(|| format!("make {} nonblocking", path.display()))?;
    let listener = UnixListener::from_std(listener).with_context(|| format!("register {} with tokio", path.display()))?;
    Ok(BoundSocket { listener, path_guard })
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    remove_stale_socket_after_probe(path, || {}).await
}

async fn remove_stale_socket_after_probe(path: &Path, after_refused_probe: impl FnOnce()) -> Result<()> {
    let first = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => meta,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    let identity = FileIdentity::of(&first);
    let probe = tokio::time::timeout(SOCKET_PROBE_TIMEOUT, tokio::net::UnixStream::connect(path)).await;
    match probe {
        Ok(Ok(_)) => bail!("{} already has a live listener", path.display()),
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) && cfg!(target_os = "linux") => {
            after_refused_probe();
            let current = std::fs::symlink_metadata(path)
                .with_context(|| format!("recheck stale socket {}", path.display()))?;
            if !current.file_type().is_socket() || !identity.matches(&current) {
                bail!("{} changed while checking whether it was stale", path.display());
            }
            // The socket-directory lock makes this compare-and-delete stable
            // between cooperating kilnd processes. POSIX has no atomic
            // compare-and-unlink primitive, so hostile root remains trusted.
            std::fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))?;
            Ok(())
        }
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => Err(e).with_context(|| {
            format!(
                "probe existing socket {} was inconclusive on this platform; refusing to remove it",
                path.display()
            )
        }),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => match std::fs::symlink_metadata(path) {
            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => bail!("{} changed while checking whether it was stale", path.display()),
        },
        Ok(Err(e)) => Err(e).with_context(|| format!("probe existing socket {}; refusing to remove it", path.display())),
        Err(_) => bail!("timed out probing existing socket {}; refusing to remove it", path.display()),
    }
}

/// Serves until `shutdown` resolves, then: refuses new work and stops
/// accepting connections, lets in-flight requests finish for `grace`,
/// cancels running executions, waits briefly for their replies, and drains
/// accepted manager-owned operations even if their RPCs disconnected.
pub async fn serve<R: Runtime>(
    manager: Arc<Manager<R>>,
    socket: BoundSocket,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) -> Result<()> {
    serve_with_final_wait_owned(manager, socket, shutdown, grace, FINAL_WAIT).await
}

async fn serve_with_final_wait_owned<R: Runtime>(
    manager: Arc<Manager<R>>,
    socket: BoundSocket,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
    final_wait: Duration,
) -> Result<()> {
    let BoundSocket { listener, mut path_guard } = socket;
    let result = serve_with_final_wait(manager.clone(), listener, shutdown, grace, final_wait).await;
    let cleanup = path_guard.cleanup();
    // State ownership outlives transport shutdown, operation draining, and
    // conditional socket cleanup regardless of how the caller manages Arcs.
    drop(manager);
    match result {
        Err(e) => {
            if let Err(cleanup_error) = cleanup {
                warn!(error = %format!("{cleanup_error:#}"), "socket cleanup also failed after serving error");
            }
            Err(e)
        }
        Ok(()) => cleanup,
    }
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
        let socket = tmp.path().join("run/kilnd.sock");
        let alternate = tmp.path().join("run/alternate.sock");
        let state_dir = tmp.path().join("state");
        let fake = FakeRuntime::default();
        let remove_gate = FakeGate::default();
        fake.state().remove_before_delete = Some(remove_gate.clone());
        let store = Store::open(&state_dir).unwrap();
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
        // expire, but both ownership guards must remain alive for
        // manager-owned cleanup and its terminal SQLite publication.
        let owned_socket = bind(&socket, None).await.unwrap();
        let mut server = tokio::spawn(serve_with_final_wait_owned(
            manager,
            owned_socket,
            async {},
            Duration::ZERO,
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server).await.is_err(),
            "server exited at its final RPC deadline while compensation was paused"
        );
        let state_error = Store::open(&state_dir)
            .err()
            .expect("state ownership was released before operation drain");
        assert!(state_error.to_string().contains("state directory already owned"), "{state_error:#}");
        let socket_error = bind(&alternate, None)
            .await
            .err()
            .expect("socket ownership was released before operation drain");
        assert!(socket_error.to_string().contains("socket directory already owned"), "{socket_error:#}");

        remove_gate.release();
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
        assert!(!socket.exists(), "graceful shutdown left its owned socket behind");
        let store = Store::open(&state_dir).unwrap();
        let row = store.sandboxes(true).unwrap().remove(0);
        assert_eq!(row.state, SandboxState::Failed);
        assert!(row.failure_reason.as_deref().unwrap().contains("backend removed"));
        assert!(fake.state().sandboxes.is_empty());
        drop(store);
        let next = bind(&alternate, None).await.unwrap();
        drop(next);
    }

    #[tokio::test]
    async fn shutdown_without_transport_honors_grace_and_drains_exec_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("run/kilnd.sock");
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
        let BoundSocket { listener, path_guard: _path_guard } = bind(&socket, None).await.unwrap();
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

    #[tokio::test]
    async fn shutdown_holds_both_locks_while_terminal_execution_write_retries() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("run/kilnd.sock");
        let alternate = tmp.path().join("run/alternate.sock");
        let state_dir = tmp.path().join("state");
        let fake = FakeRuntime::default();
        let store = Store::open(&state_dir).unwrap();
        let finish_rejection = store.execution_finish_rejection_flag();
        store.reject_execution_finishes().unwrap();
        let manager = Arc::new(Manager::new(fake.clone(), store, Limits::default()));
        let sandbox = manager.create(CreateRequest::default()).await.unwrap();
        let waiter = tokio::spawn({
            let manager = manager.clone();
            let sandbox_id = sandbox.id.clone();
            async move {
                manager
                    .exec(ExecRequest {
                        sandbox_id,
                        argv: vec!["echo".into(), "completed".into()],
                        stdin: vec![],
                        timeout_ms: 0,
                    })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if manager.health().await.unwrap().detail.contains("finalization write") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("execution did not enter terminal-publication retry");
        let execution_id = manager.get(&sandbox.id, 1).unwrap().1[0].id.clone();
        assert_eq!(manager.execution(&execution_id).unwrap().state, ExecutionState::Running);
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        let owned_socket = bind(&socket, None).await.unwrap();
        let mut server = tokio::spawn(serve_with_final_wait_owned(
            manager,
            owned_socket,
            async {},
            Duration::ZERO,
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server).await.is_err(),
            "server exited while terminal publication was retrying"
        );
        let state_error = Store::open(&state_dir)
            .err()
            .expect("state ownership was released during terminal-publication retry");
        assert!(state_error.to_string().contains("state directory already owned"), "{state_error:#}");
        let socket_error = bind(&alternate, None)
            .await
            .err()
            .expect("socket ownership was released during terminal-publication retry");
        assert!(socket_error.to_string().contains("socket directory already owned"), "{socket_error:#}");

        finish_rejection.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
        assert!(!socket.exists(), "graceful shutdown left its owned socket behind");
        let store = Store::open(&state_dir).unwrap();
        let execution = store.execution(&execution_id).unwrap().unwrap();
        assert_eq!(execution.state, ExecutionState::Exited);
        assert_eq!(execution.stdout.data, b"completed\n");
        drop(store);
        let next = bind(&alternate, None).await.unwrap();
        drop(next);
        assert_eq!(fake.state().active_execs, 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stale_probe_refuses_a_socket_replaced_before_the_identity_check() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("kilnd.sock");
        let original = dir.join("original.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let original_inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let probed = Arc::new(std::sync::Barrier::new(2));
        let replaced = Arc::new(std::sync::Barrier::new(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let replacer = std::thread::spawn({
            let path = path.clone();
            let original = original.clone();
            let probed = probed.clone();
            let replaced = replaced.clone();
            move || {
                probed.wait();
                std::fs::rename(&path, &original).unwrap();
                let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
                tx.send(replacement).unwrap();
                replaced.wait();
            }
        });

        let error = remove_stale_socket_after_probe(&path, || {
            probed.wait();
            replaced.wait();
        })
        .await
        .expect_err("a replacement socket was deleted as stale");
        assert!(error.to_string().contains("changed"), "{error:#}");
        let replacement = rx.recv().unwrap();
        let replacement_inode = std::fs::symlink_metadata(&path).unwrap().ino();
        assert_ne!(replacement_inode, original_inode);
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        drop(replacement);
        replacer.join().unwrap();
    }
}
