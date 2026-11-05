//! The Unix socket and the server's lifecycle: bind with tight permissions,
//! serve, and shut down gracefully.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kilnd_api::v1::kilnd_service_server::KilndServiceServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::server::Connected;
use tracing::{info, warn};

use crate::admission::{ConnectionLane, ConnectionPermit};
use crate::lock::ExclusiveFileLock;
use crate::manager::Manager;
use crate::runtime::Runtime;
use crate::service::Service;
use crate::store::prepare_socket_directory;
use crate::sys::socket::{
    Removal, Seen, SocketGeneration, remove_socket_generation, socket_generation_at,
};

/// How long to wait for in-flight requests after running executions were
/// canceled, before exiting regardless.
const FINAL_WAIT: Duration = Duration::from_secs(10);
const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Who the kernel says connected, attached to every request on the connection.
/// Clients cannot set request extensions, and `None` means the kernel gave no
/// answer: the service refuses such a caller rather than assuming an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerIdentity {
    pub uid: Option<u32>,
    /// The connection's slot: a reserved one serves Health and cleanup only.
    pub lane: ConnectionLane,
}

/// The HTTP/2 client connection preface, `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.
const HTTP2_PREFACE_BYTES: usize = 24;

/// The deadline for a connection's first 24 bytes (B6-BI-03). Until the preface is in,
/// every read also polls the deadline, so an idle socket is woken and failed at the
/// deadline even while no byte arrives; transport then closes it and drops its slot.
struct PrefaceDeadline {
    remaining: usize,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

struct AdmittedUnixStream {
    stream: UnixStream,
    peer: PeerIdentity,
    preface: Option<PrefaceDeadline>,
    _permit: ConnectionPermit,
}

impl Connected for AdmittedUnixStream {
    type ConnectInfo = PeerIdentity;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer
    }
}

impl AsyncRead for AdmittedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(preface) = self.preface.as_mut()
            && preface.deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no HTTP/2 preface before the connection deadline",
            )));
        }
        let before = buf.filled().len();
        let read = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = read {
            let got = buf.filled().len() - before;
            if let Some(preface) = self.preface.as_mut() {
                preface.remaining = preface.remaining.saturating_sub(got);
                if preface.remaining == 0 {
                    self.preface = None;
                }
            }
        }
        read
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

/// A listener plus exclusive ownership of its directory and pathname.
/// Cleanup is conditional on the pathname still identifying this instance's
/// socket, so a replacement is never unlinked on shutdown.
pub struct BoundSocket {
    listener: UnixListener,
    path_guard: SocketPathGuard,
}

struct SocketPathGuard {
    path: PathBuf,
    name: OsString,
    generation: SocketGeneration,
    active: bool,
    _directory_lock: ExclusiveFileLock,
    directory: File,
}

impl SocketPathGuard {
    /// Removes kilnd's own API socket at shutdown, only while it is still the
    /// generation (device, inode and birth time) this guard bound, read through the
    /// socket directory's descriptor immediately before the unlink (design 7.1).
    fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        match remove_socket_generation(&self.directory, &self.name, &self.generation)
            .with_context(|| format!("remove owned socket {}", self.path.display()))?
        {
            Removal::Removed | Removal::Gone => {}
            Removal::Replaced => {
                warn!(socket = %self.path.display(), "socket path was replaced; leaving replacement untouched");
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
    remove_stale_socket(&directory.file, name, &socket_path).await?;

    // A losing invocation must not alter an incumbent directory's access.
    // Permission changes occur only after this process owns the directory
    // lock and has ruled out a live listener.
    set_directory_access(&directory.file, gid, dir_mode, &directory.path)?;
    ensure_directory_path_identity(dir, &meta)?;
    ensure_directory_path_identity(&directory.path, &meta)?;

    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    let generation = match socket_generation_at(&directory.file, name)
        .with_context(|| format!("inspect bound socket {}", socket_path.display()))?
    {
        Seen::Socket(generation) => generation,
        _ => bail!("{} did not become a socket after bind", path.display()),
    };
    let path_guard = SocketPathGuard {
        path: socket_path.clone(),
        name: name.to_os_string(),
        generation,
        active: true,
        _directory_lock: directory_lock,
        directory: directory.file,
    };
    chown(&socket_path, None, gid).with_context(|| format!("chown {}", socket_path.display()))?;
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
        bail!(
            "socket directory {} changed while preparing bind",
            path.display()
        );
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

async fn remove_stale_socket(directory: &File, name: &OsStr, path: &Path) -> Result<()> {
    remove_stale_socket_after_probe(directory, name, path, || {}).await
}

/// Removes a stale API socket only after a refused connection, and only while the name
/// still shows the generation (device, inode and birth time) read before the probe,
/// through the socket directory's descriptor (design 7.1). A changed path is left
/// alone.
async fn remove_stale_socket_after_probe(
    directory: &File,
    name: &OsStr,
    path: &Path,
    after_refused_probe: impl FnOnce(),
) -> Result<()> {
    let generation = match socket_generation_at(directory, name)
        .with_context(|| format!("stat {}", path.display()))?
    {
        Seen::Socket(generation) => generation,
        Seen::NotASocket => bail!("{} exists and is not a socket", path.display()),
        Seen::Nothing => return Ok(()),
    };
    let probe =
        tokio::time::timeout(SOCKET_PROBE_TIMEOUT, tokio::net::UnixStream::connect(path)).await;
    match probe {
        Ok(Ok(_)) => bail!("{} already has a live listener", path.display()),
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) && cfg!(target_os = "linux") => {
            after_refused_probe();
            // The socket-directory lock makes this compare-and-delete stable between
            // cooperating kilnd processes; the birth time makes it refuse an inode-reused
            // replacement. POSIX has no atomic compare-and-unlink primitive, so the
            // interval between the final read and the unlink remains.
            match remove_socket_generation(directory, name, &generation)
                .with_context(|| format!("remove stale socket {}", path.display()))?
            {
                Removal::Removed => {}
                Removal::Replaced | Removal::Gone => bail!(
                    "{} changed while checking whether it was stale",
                    path.display()
                ),
            }
            Ok(())
        }
        Ok(Err(e)) if e.raw_os_error() == Some(libc::ECONNREFUSED) => Err(e).with_context(|| {
            format!(
                "probe existing socket {} was inconclusive on this platform; refusing to remove it",
                path.display()
            )
        }),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            match socket_generation_at(directory, name) {
                Ok(Seen::Nothing) => Ok(()),
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
    let preface_timeout = limits.connection_preface_timeout;
    let incoming = UnixListenerStream::new(listener).filter_map(move |conn| match conn {
        Ok(stream) => {
            // The socket's credentials are fixed at connect, so this one read is what
            // admission shares by, what the log shows and what every request is
            // authorized as. It is one getsockopt, before any byte is read.
            let credentials = stream.peer_cred();
            let uid = credentials.as_ref().ok().map(|c| c.uid());
            // B6-BI-03: a general slot within this UID's share, else one of the slots
            // held back for Health and cleanup, else (UID 0 only) the root slot, else
            // the socket is closed here.
            let permit = admission.try_connection(uid).ok()?;
            match &credentials {
                Ok(c) => info!(
                    uid = c.uid(),
                    gid = c.gid(),
                    pid = c.pid().unwrap_or(0),
                    reserved = permit.lane().health_and_cleanup_only(),
                    root_slot = permit.lane() == ConnectionLane::Root,
                    "client connected"
                ),
                Err(e) => warn!(error = %e, "client connected; peer credentials unavailable"),
            }
            Some(Ok(AdmittedUnixStream {
                stream,
                peer: PeerIdentity {
                    uid,
                    lane: permit.lane(),
                },
                preface: Some(PrefaceDeadline {
                    remaining: HTTP2_PREFACE_BYTES,
                    deadline: Box::pin(tokio::time::sleep(preface_timeout)),
                }),
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
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::manager::{CreateRequest, ExecRequest, Limits};
    use crate::model::{ExecutionState, SandboxState};
    use crate::runtime::fake::{FakeGate, FakeRuntime};
    use crate::store::Store;
    use std::os::unix::fs::DirBuilderExt;

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
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&safe_root)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state_root)
            .unwrap();
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

        let error =
            bind_away_from_after_directory_check(&socket, Some(1), Some(state_identity), || {
                std::fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&state_root, &alias).unwrap();
            })
            .await
            .err()
            .expect("replaced socket-directory alias was accepted");

        assert!(
            error.to_string().contains("changed while preparing"),
            "{error:#}"
        );
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

    async fn wait_admitted(manager: &Manager<FakeRuntime>, current: u64, rejected: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let snapshot = manager.admission().snapshot().connections;
                if (snapshot.current, snapshot.rejected) == (current, rejected) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "connections never reached {current} admitted and {rejected} rejected: {:?}",
                manager.admission().snapshot()
            )
        });
    }

    async fn client(
        path: &Path,
    ) -> kilnd_api::v1::kilnd_service_client::KilndServiceClient<tonic::transport::Channel> {
        let path = path.to_path_buf();
        let channel = tonic::transport::Endpoint::try_from("http://kilnd.invalid")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        UnixStream::connect(path).await?,
                    ))
                }
            }))
            .await
            .unwrap();
        kilnd_api::v1::kilnd_service_client::KilndServiceClient::new(channel)
    }

    async fn serve_with(
        limits: Limits,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Arc<Manager<FakeRuntime>>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("run/kilnd.sock");
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            limits,
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
        (temp, path, manager, stop_tx, server)
    }

    /// B6-BI-03 on the real transport: one UID's idle sockets get its share of general
    /// slots and one reserved slot, the rest are closed at accept, and every admitted one
    /// that never sends the HTTP/2 preface (none, or 23 of its 24 bytes) is closed at
    /// the preface deadline with its slot released. A connection that sends the preface
    /// in time stays open past the deadline.
    #[tokio::test]
    async fn b7_idle_sockets_are_dropped_at_the_preface_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let deadline = Duration::from_millis(400);
        let (_temp, path, manager, stop_tx, server) = serve_with(Limits {
            max_connections: 8,
            reserved_connections: 2,
            max_connections_per_uid: 3,
            connection_preface_timeout: deadline,
            ..Limits::default()
        })
        .await;
        // SAFETY: geteuid has no preconditions.
        let me = Some(unsafe { libc::geteuid() });
        let started = std::time::Instant::now();
        let mut idle = Vec::new();
        for _ in 0..10 {
            idle.push(UnixStream::connect(&path).await.unwrap());
        }
        // One of the admitted four is a slow drip: 23 bytes, never the 24th.
        wait_admitted(&manager, 4, 6).await;
        assert_eq!(manager.admission().connections_held_by(me), (3, 1));
        assert_eq!(manager.admission().snapshot().rejected_connection_shares, 6);
        for stream in &mut idle {
            stream
                .write_all(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r"[..23])
                .await
                .ok();
        }
        let mut closed = Vec::new();
        for mut stream in idle {
            let mut byte = [0; 64];
            let closed_at = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => break started.elapsed(),
                        Ok(_) => {}
                    }
                }
            })
            .await
            .expect("an idle socket outlived the preface deadline");
            closed.push(closed_at);
        }
        let late = closed.iter().filter(|t| **t >= deadline).count();
        assert!(late >= 4, "the admitted sockets closed early: {closed:?}");
        wait_admitted(&manager, 0, 6).await;
        assert_eq!(manager.admission().connections_held_by(me), (0, 0));

        // A real client sends its preface at once and stays past the deadline.
        let mut live = client(&path).await;
        tokio::time::sleep(deadline * 2).await;
        live.health(kilnd_api::v1::HealthRequest {}).await.unwrap();
        assert_eq!(manager.admission().snapshot().connections.current, 1);
        drop(live);
        wait_admitted(&manager, 0, 6).await;
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// B6-BI-03: once a UID holds its whole general share, its next connection gets a
    /// reserved slot, where Health, Get and Delete are served and every other RPC is
    /// refused; and a further connection from it is closed.
    #[tokio::test]
    async fn b7_a_reserved_slot_serves_health_and_cleanup_only() {
        use kilnd_api::v1 as pb;
        let (_temp, path, manager, stop_tx, server) = serve_with(Limits {
            max_connections: 4,
            reserved_connections: 1,
            max_connections_per_uid: 2,
            ..Limits::default()
        })
        .await;
        let mut general = client(&path).await;
        let _second = client(&path).await;
        let id = general
            .create_sandbox(pb::CreateSandboxRequest::default())
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
            .id;
        wait_admitted(&manager, 2, 0).await;
        let mut reserved = client(&path).await;
        wait_admitted(&manager, 3, 0).await;
        assert_eq!(
            manager.admission().snapshot().reserved_connections.current,
            1
        );
        reserved.health(pb::HealthRequest {}).await.unwrap();
        // Every ordinary RPC, each valid on the general connection (B7 milestone 2,
        // LOW-2: Exec and GetExecution too).
        let exec = || pb::ExecRequest {
            sandbox_id: id.clone(),
            argv: vec!["echo".into(), "x".into()],
            ..Default::default()
        };
        let execution = general
            .exec(exec())
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap()
            .id;
        general
            .get_execution(pb::GetExecutionRequest {
                id: execution.clone(),
            })
            .await
            .unwrap();
        for status in [
            reserved
                .create_sandbox(pb::CreateSandboxRequest::default())
                .await
                .unwrap_err(),
            reserved
                .list_sandboxes(pb::ListSandboxesRequest::default())
                .await
                .unwrap_err(),
            reserved.exec(exec()).await.unwrap_err(),
            reserved
                .get_execution(pb::GetExecutionRequest { id: execution })
                .await
                .unwrap_err(),
        ] {
            assert_eq!(status.code(), tonic::Code::ResourceExhausted);
            assert!(status.message().contains("reserved slot"), "{status:?}");
        }
        reserved
            .get_sandbox(pb::GetSandboxRequest {
                id: id.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        reserved
            .delete_sandbox(pb::DeleteSandboxRequest { id })
            .await
            .unwrap();
        // The UID's share and its reserved slot are both held: the next is closed.
        let mut excess = UnixStream::connect(&path).await.unwrap();
        let mut byte = [0];
        let read = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut excess, &mut byte),
        )
        .await
        .expect("the excess socket stayed open");
        assert!(matches!(read, Ok(0) | Err(_)));
        wait_admitted(&manager, 3, 1).await;
        stop_tx.send(()).unwrap();
        drop((general, reserved));
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
        let store = Store::reopen_after_restart(&state_dir);
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
        let store = Store::reopen_after_restart(&state_dir);
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

        let directory = File::open(&dir).unwrap();
        let error =
            remove_stale_socket_after_probe(&directory, OsStr::new("kilnd.sock"), &path, || {
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

    /// B4 recheck 5 finding 2, the PoC as a regression: once root unlinks the stale
    /// socket, ext4 hands its inode number straight to a live replacement. The birth
    /// time differs, so cleanup refuses and the replacement keeps its name.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs an ext4 /var/tmp that reuses inodes; run by scripts/b4-vm-tests.sh"]
    async fn b4_linux_root_stale_socket_inode_reuse_is_refused() {
        let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
        let dir = tmp.path().join("run");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("kilnd.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let original = std::fs::symlink_metadata(&path).unwrap();
        let replacement = std::sync::Mutex::new(None);
        let directory = File::open(&dir).unwrap();

        let error =
            remove_stale_socket_after_probe(&directory, OsStr::new("kilnd.sock"), &path, || {
                std::fs::remove_file(&path).unwrap();
                for _ in 0..100_000 {
                    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
                    let seen = std::fs::symlink_metadata(&path).unwrap();
                    if seen.dev() == original.dev() && seen.ino() == original.ino() {
                        *replacement.lock().unwrap() = Some(listener);
                        return;
                    }
                    drop(listener);
                    std::fs::remove_file(&path).unwrap();
                }
                panic!("filesystem did not reuse the stale socket inode");
            })
            .await
            .expect_err("the reused-inode replacement was deleted as stale");
        assert!(error.to_string().contains("changed"), "{error:#}");
        assert!(
            replacement.lock().unwrap().is_some(),
            "the inode was reused"
        );
        assert!(path.exists(), "the live replacement was unlinked");
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        let now = std::fs::symlink_metadata(&path).unwrap();
        eprintln!(
            "B4 evidence: stale socket inode {} reused by a live replacement; birth time equal: \
             {}; cleanup refused it",
            now.ino(),
            now.created().ok() == original.created().ok()
        );

        // The owned-socket guard has the same identity: a replacement that reused the
        // bound inode number is left in place at shutdown.
        let lock_dir = tmp.path().join("guard");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&lock_dir)
            .unwrap();
        let bound = bind(&lock_dir.join("kilnd.sock"), None).await.unwrap();
        let guarded = lock_dir.join("kilnd.sock");
        let before = std::fs::symlink_metadata(&guarded).unwrap();
        // A bound listener pins its inode. BoundSocket drops the listener before the
        // guard, so the replacement window is after the listener has closed.
        let BoundSocket {
            listener,
            path_guard,
        } = bound;
        drop(listener);
        let mut reused = None;
        std::fs::remove_file(&guarded).unwrap();
        for _ in 0..100_000 {
            let listener = std::os::unix::net::UnixListener::bind(&guarded).unwrap();
            let seen = std::fs::symlink_metadata(&guarded).unwrap();
            if seen.dev() == before.dev() && seen.ino() == before.ino() {
                reused = Some(listener);
                break;
            }
            drop(listener);
            std::fs::remove_file(&guarded).unwrap();
        }
        assert!(
            reused.is_some(),
            "filesystem did not reuse the bound socket inode"
        );
        drop(path_guard);
        assert!(
            guarded.exists(),
            "the guard unlinked an inode-reused replacement"
        );
        assert!(std::os::unix::net::UnixStream::connect(&guarded).is_ok());
        let now = std::fs::symlink_metadata(&guarded).unwrap();
        eprintln!(
            "B4 evidence: bound socket inode {} reused after the listener closed; birth time \
             equal: {}; the guard left it",
            now.ino(),
            now.created().ok() == before.created().ok()
        );
        drop(reused);
    }
}
