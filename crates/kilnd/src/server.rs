//! The Unix socket and the server's lifecycle: bind with tight permissions,
//! serve, and shut down gracefully.

use std::future::Future;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kilnd_api::v1::kilnd_service_server::KilndServiceServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::server::{Connected, UdsConnectInfo};
use tracing::{info, warn};

use crate::lock::ExclusiveFileLock;
use crate::manager::Manager;
use crate::runtime::Runtime;
use crate::service::Service;
use crate::store::prepare_socket_directory;

/// How long to wait for in-flight requests after running executions were
/// canceled, before exiting regardless.
const FINAL_WAIT: Duration = Duration::from_secs(10);
const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

struct AdmittedUnixStream {
    stream: UnixStream,
    _permit: OwnedSemaphorePermit,
}

impl Connected for AdmittedUnixStream {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for AdmittedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AdmittedUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
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
    _directory: File,
}

impl SocketPathGuard {
    fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.file_type().is_socket() && self.identity.matches(&meta) => {
                std::fs::remove_file(&self.path)
                    .with_context(|| format!("remove owned socket {}", self.path.display()))?;
            }
            Ok(_) => {
                warn!(socket = %self.path.display(), "socket path was replaced; leaving replacement untouched");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("inspect owned socket {}", self.path.display()));
            }
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
    bind_away_from(path, gid, None).await
}

/// Binds the API socket while refusing a directory whose device/inode is the
/// pinned state directory. The identity check happens before socket-directory
/// ownership or permission changes.
pub async fn bind_away_from(
    path: &Path,
    gid: Option<u32>,
    forbidden_directory: Option<(u64, u64)>,
) -> Result<BoundSocket> {
    bind_away_from_after_directory_check(path, gid, forbidden_directory, || {}).await
}

async fn bind_away_from_after_directory_check(
    path: &Path,
    gid: Option<u32>,
    forbidden_directory: Option<(u64, u64)>,
    after_directory_check: impl FnOnce(),
) -> Result<BoundSocket> {
    let dir = path.parent().context("socket path has no directory")?;
    let name = path.file_name().context("socket path has no filename")?;
    let (dir_mode, sock_mode) = if gid.is_some() {
        (0o750, 0o660)
    } else {
        (0o700, 0o600)
    };
    let directory = prepare_socket_directory(dir)?;
    let socket_path = directory.path.join(name);
    let meta = directory
        .file
        .metadata()
        .with_context(|| format!("inspect pinned socket directory {}", dir.display()))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if directory.path == Path::new("/") {
        bail!("socket directory must not be the filesystem root");
    }
    if forbidden_directory == Some((meta.dev(), meta.ino())) {
        bail!(
            "--socket directory and --state-dir must be different so socket access cannot widen state permissions"
        );
    }
    if meta.uid() != euid {
        bail!(
            "{} must be owned by uid {euid}, found uid {}",
            dir.display(),
            meta.uid()
        );
    }
    if meta.permissions().mode() & 0o022 != 0 {
        bail!(
            "{} is writable by group or others (mode {:o})",
            dir.display(),
            meta.permissions().mode() & 0o777
        );
    }
    after_directory_check();
    ensure_directory_path_identity(dir, &meta)?;

    let lock_path = directory.path.join(".kilnd.socket.lock");
    let directory_lock = ExclusiveFileLock::acquire_at(
        &directory.file,
        std::ffi::OsStr::new(".kilnd.socket.lock"),
        &lock_path,
        "socket directory",
    )?;
    remove_stale_socket(&socket_path).await?;

    // A losing invocation must not alter an incumbent directory's access.
    // Permission changes occur only after this process owns the directory
    // lock and has ruled out a live listener.
    set_directory_access(&directory.file, gid, dir_mode, &directory.path)?;
    ensure_directory_path_identity(dir, &meta)?;
    ensure_directory_path_identity(&directory.path, &meta)?;

    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    let socket_meta = std::fs::symlink_metadata(&socket_path)
        .with_context(|| format!("inspect bound socket {}", socket_path.display()))?;
    if !socket_meta.file_type().is_socket() {
        bail!("{} did not become a socket after bind", path.display());
    }
    let path_guard = SocketPathGuard {
        path: socket_path.clone(),
        identity: FileIdentity::of(&socket_meta),
        active: true,
        _directory_lock: directory_lock,
        _directory: directory.file,
    };
    chown(&socket_path, None, gid)
        .with_context(|| format!("chown {}", socket_path.display()))?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(sock_mode))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("make {} nonblocking", path.display()))?;
    let listener = UnixListener::from_std(listener)
        .with_context(|| format!("register {} with tokio", path.display()))?;
    Ok(BoundSocket {
        listener,
        path_guard,
    })
}

fn ensure_directory_path_identity(path: &Path, expected: &std::fs::Metadata) -> Result<()> {
    let observed = std::fs::metadata(path)
        .with_context(|| format!("recheck socket directory {}", path.display()))?;
    if observed.dev() != expected.dev() || observed.ino() != expected.ino() {
        bail!("socket directory {} changed while preparing bind", path.display());
    }
    Ok(())
}

fn set_directory_access(file: &File, gid: Option<u32>, mode: u32, path: &Path) -> Result<()> {
    let unchanged_uid = !0 as libc::uid_t;
    let target_gid = gid.map_or(!0 as libc::gid_t, |gid| gid as libc::gid_t);
    // SAFETY: file is a live directory descriptor and -1 leaves an ownership
    // field unchanged on POSIX systems.
    if unsafe { libc::fchown(file.as_raw_fd(), unchanged_uid, target_gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fchown {}", path.display()));
    }
    // SAFETY: file is a live directory descriptor and mode contains only
    // permission bits.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fchmod {}", path.display()));
    }
    Ok(())
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    remove_stale_socket_after_probe(path, || {}).await
}

async fn remove_stale_socket_after_probe(
    path: &Path,
    after_refused_probe: impl FnOnce(),
) -> Result<()> {
    let first = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => meta,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    let identity = FileIdentity::of(&first);
    let probe =
        tokio::time::timeout(SOCKET_PROBE_TIMEOUT, tokio::net::UnixStream::connect(path)).await;
    match probe {
        Ok(Ok(_)) => bail!("{} already has a live listener", path.display()),
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) && cfg!(target_os = "linux") => {
            after_refused_probe();
            let current = std::fs::symlink_metadata(path)
                .with_context(|| format!("recheck stale socket {}", path.display()))?;
            if !current.file_type().is_socket() || !identity.matches(&current) {
                bail!(
                    "{} changed while checking whether it was stale",
                    path.display()
                );
            }
            // The socket-directory lock makes this compare-and-delete stable
            // between cooperating kilnd processes. POSIX has no atomic
            // compare-and-unlink primitive, so hostile root remains trusted.
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
            Ok(())
        }
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => Err(e).with_context(|| {
            format!(
                "probe existing socket {} was inconclusive on this platform; refusing to remove it",
                path.display()
            )
        }),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(path) {
                Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => bail!(
                    "{} changed while checking whether it was stale",
                    path.display()
                ),
            }
        }
        Ok(Err(e)) => Err(e).with_context(|| {
            format!(
                "probe existing socket {}; refusing to remove it",
                path.display()
            )
        }),
        Err(_) => bail!(
            "timed out probing existing socket {}; refusing to remove it",
            path.display()
        ),
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
    let BoundSocket {
        listener,
        mut path_guard,
    } = socket;
    let result =
        serve_with_final_wait(manager.clone(), listener, shutdown, grace, final_wait).await;
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
    let admission = manager.admission().clone();
    let limits = manager.limits();
    let max_streams = limits.max_streams_per_connection;
    let service = KilndServiceServer::new(Service::new(manager.clone()))
        .max_decoding_message_size(limits.max_request_bytes)
        .max_encoding_message_size(limits.max_response_bytes);
    let incoming = UnixListenerStream::new(listener).filter_map(move |conn| match conn {
        Ok(stream) => {
            let permit = admission.try_connection().ok()?;
            match stream.peer_cred() {
                Ok(c) => info!(
                    uid = c.uid(),
                    gid = c.gid(),
                    pid = c.pid().unwrap_or(0),
                    "client connected"
                ),
                Err(e) => warn!(error = %e, "client connected; peer credentials unavailable"),
            }
            Some(Ok(AdmittedUnixStream {
                stream,
                _permit: permit,
            }))
        }
        Err(e) => {
            warn!(error = %e, "accept failed");
            Some(Err(e))
        }
    });
    let stop = CancellationToken::new();
    let server = tonic::transport::Server::builder()
        .max_concurrent_streams(Some(
            u32::try_from(max_streams).expect("validated stream count fits u32"),
        ))
        .concurrency_limit_per_connection(max_streams)
        .load_shed(true)
        .initial_stream_window_size(Some(64 * 1024))
        .initial_connection_window_size(Some(256 * 1024))
        .http2_adaptive_window(Some(false))
        .http2_max_header_list_size(Some(16 * 1024))
        .max_frame_size(Some(16 * 1024))
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, stop.clone().cancelled_owned());
    tokio::pin!(server);
    tokio::pin!(shutdown);

    let mut server_result = tokio::select! {
        r = &mut server => Some(r),
        () = &mut shutdown => None,
    };
    let requested = server_result.is_none();
    info!(
        grace_secs = grace.as_secs(),
        "shutting down: refusing new work, waiting for requests and owned operations"
    );
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
    use std::os::unix::fs::DirBuilderExt;
    use crate::manager::{CreateRequest, ExecRequest, Limits};
    use crate::model::{ExecutionState, SandboxState};
    use crate::runtime::fake::{FakeGate, FakeRuntime};
    use crate::store::Store;

    async fn wait_connections(manager: &Manager<FakeRuntime>, expected: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let current = manager.admission().snapshot().connections.current;
                assert!(current <= 2, "connection capacity exceeded: {current}");
                if current == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("connection permits did not reach expected use");
    }

    #[tokio::test]
    async fn socket_directory_aliases_cannot_widen_state_permissions() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = temp.path().join("state");
        let store = Store::open(&state).unwrap();
        let state_identity = store.state_directory_identity().unwrap().unwrap();
        std::os::unix::fs::symlink(temp.path(), temp.path().join("alias")).unwrap();
        let mut aliases = vec![
            state.join("../state/kilnd.sock"),
            temp.path().join("alias/state/kilnd.sock"),
        ];
        let canonical_state = std::fs::canonicalize(&state).unwrap();
        if canonical_state != state {
            aliases.push(canonical_state.join("kilnd.sock"));
        }

        for socket in aliases {
            let error = bind_away_from(&socket, Some(1), Some(state_identity))
                .await
                .err()
                .expect("socket alias to the state directory was accepted");
            assert!(error.to_string().contains("must be different"), "{error:#}");
            assert_eq!(
                std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
                0o700,
                "rejected socket alias changed state-directory permissions"
            );
            assert!(!socket.exists());
        }
    }

    #[tokio::test]
    async fn socket_directory_swap_cannot_redirect_lock_or_permissions_to_state() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let safe_root = temp.path().join("safe");
        let state_root = temp.path().join("state-root");
        std::fs::DirBuilder::new().mode(0o700).create(&safe_root).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&state_root).unwrap();
        let safe_directory = safe_root.join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&safe_directory)
            .unwrap();
        let state = state_root.join("run");
        let store = Store::open(&state).unwrap();
        let state_identity = store.state_directory_identity().unwrap().unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&safe_root, &alias).unwrap();
        let socket = alias.join("run/kilnd.sock");

        let error = bind_away_from_after_directory_check(
            &socket,
            Some(1),
            Some(state_identity),
            || {
                std::fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&state_root, &alias).unwrap();
            },
        )
        .await
        .err()
        .expect("replaced socket-directory alias was accepted");

        assert!(error.to_string().contains("changed while preparing"), "{error:#}");
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for directory in [&state, &safe_directory] {
            assert!(!directory.join(".kilnd.socket.lock").exists());
            assert!(!directory.join("kilnd.sock").exists());
        }
    }

    #[tokio::test]
    async fn raw_connection_ceiling_closes_excess_and_recovers_fd_permits() {
        use tokio::io::AsyncReadExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("run/kilnd.sock");
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_connections: 2,
                ..Limits::default()
            },
        ));
        let listener = bind(&path, None).await.unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(
            manager.clone(),
            listener,
            async {
                let _ = stop_rx.await;
            },
            Duration::from_secs(1),
        ));
        let first = UnixStream::connect(&path).await.unwrap();
        wait_connections(&manager, 1).await;
        let second = UnixStream::connect(&path).await.unwrap();
        wait_connections(&manager, 2).await;
        for rejected in 1..=8 {
            let mut excess = UnixStream::connect(&path).await.unwrap();
            let mut byte = [0];
            let read = tokio::time::timeout(Duration::from_secs(5), excess.read(&mut byte))
                .await
                .expect("excess socket remained open");
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "rejected socket carried transport bytes"
            );
            let snapshot = manager.admission().snapshot().connections;
            assert_eq!(snapshot.current, 2);
            assert_eq!(snapshot.rejected, rejected);
        }
        drop((first, second));
        wait_connections(&manager, 0).await;
        let recovered = UnixStream::connect(&path).await.unwrap();
        wait_connections(&manager, 1).await;
        drop(recovered);
        wait_connections(&manager, 0).await;
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_detached_compensation_beyond_final_rpc_wait() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
            tokio::time::timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err(),
            "server exited at its final RPC deadline while compensation was paused"
        );
        let state_error = Store::open(&state_dir)
            .err()
            .expect("state ownership was released before operation drain");
        assert!(
            state_error
                .to_string()
                .contains("state directory already owned"),
            "{state_error:#}"
        );
        let socket_error = bind(&alternate, None)
            .await
            .err()
            .expect("socket ownership was released before operation drain");
        assert!(
            socket_error
                .to_string()
                .contains("socket directory already owned"),
            "{socket_error:#}"
        );

        remove_gate.release();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            !socket.exists(),
            "graceful shutdown left its owned socket behind"
        );
        let store = Store::open(&state_dir).unwrap();
        let row = store.sandboxes(true).unwrap().remove(0);
        assert_eq!(row.state, SandboxState::Failed);
        assert!(
            row.failure_reason
                .as_deref()
                .unwrap()
                .contains("backend removed")
        );
        assert!(fake.state().sandboxes.is_empty());
        drop(store);
        let next = bind(&alternate, None).await.unwrap();
        drop(next);
    }

    #[tokio::test]
    async fn shutdown_without_transport_honors_grace_and_drains_exec_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = tmp.path().join("run/kilnd.sock");
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
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
        let BoundSocket {
            listener,
            path_guard: _path_guard,
        } = bind(&socket, None).await.unwrap();
        let mut server = tokio::spawn(serve_with_final_wait(
            manager.clone(),
            listener,
            async {},
            Duration::from_millis(20),
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err(),
            "server exited while canceled exec cleanup was paused"
        );
        assert_eq!(manager.health().await.unwrap().running_executions, 1);

        gate.release();
        let execution = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(execution.state, ExecutionState::Canceled);
        assert_eq!(execution.failure_reason.as_deref(), Some("kilnd shut down"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fake.state().active_execs, 0);
    }

    #[tokio::test]
    async fn shutdown_holds_both_locks_while_terminal_execution_write_retries() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
                if manager
                    .health()
                    .await
                    .unwrap()
                    .detail
                    .contains("finalization write")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("execution did not enter terminal-publication retry");
        let execution_id = manager.get(&sandbox.id, 1).unwrap().1[0].id.clone();
        assert_eq!(
            manager.execution(&execution_id).unwrap().state,
            ExecutionState::Running
        );
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
            tokio::time::timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err(),
            "server exited while terminal publication was retrying"
        );
        let state_error = Store::open(&state_dir)
            .err()
            .expect("state ownership was released during terminal-publication retry");
        assert!(
            state_error
                .to_string()
                .contains("state directory already owned"),
            "{state_error:#}"
        );
        let socket_error = bind(&alternate, None)
            .await
            .err()
            .expect("socket ownership was released during terminal-publication retry");
        assert!(
            socket_error
                .to_string()
                .contains("socket directory already owned"),
            "{socket_error:#}"
        );

        finish_rejection.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            !socket.exists(),
            "graceful shutdown left its owned socket behind"
        );
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
