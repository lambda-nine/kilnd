//! Owned machine-exec transport. No protocol interpretation occurs here.
use std::future::{Future, poll_fn};
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::ExecSpec;
use super::kiln_protocol::MAX_FRAME;
use crate::model::Captured;
use crate::process::{SAFE_PATH, prepare_child};

const FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(2);
const CLI_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, Default)]
pub struct StreamState {
    pub captured: Captured,
    pub eof: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct StatusState {
    pub bytes: Vec<u8>,
    pub eof: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum Stop {
    /// Status reached EOF before CLI exit; the adapter must validate it now.
    StatusReady,
    Exited,
    TimedOut,
    Canceled,
    Transport(String),
    Panic,
}

pub struct RawResult {
    pub child_status: Option<ExitStatus>,
    pub status: StatusState,
    pub cli_stdout: StreamState,
    pub cli_stderr: StreamState,
    pub stdout: StreamState,
    pub stderr: StreamState,
}

pub struct ProbeResult {
    pub child_status: Option<ExitStatus>,
    pub status: StatusState,
    pub stderr: StreamState,
    pub stop: Stop,
}

/// Capability exchanges require actual EOF, not the generic runner's drain grace.
pub async fn probe(
    bin: &Path,
    args: &[String],
    deadline: Instant,
    cancel: &CancellationToken,
) -> io::Result<ProbeResult> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let expected_parent = unsafe { libc::getpid() };
    // SAFETY: prepare_child is restricted to async-signal-safe operations.
    unsafe {
        cmd.pre_exec(move || prepare_child(expected_parent));
    }
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(ProbeResult {
            child_status: None,
            status: Default::default(),
            stderr: Default::default(),
            stop: if cancel.is_cancelled() {
                Stop::Canceled
            } else {
                Stop::TimedOut
            },
        });
    }
    let mut child = cmd.spawn()?;
    let status = Arc::new(Mutex::new(StatusState::default()));
    let stderr = Arc::new(Mutex::new(StreamState::default()));
    let mut error_reader = spawn_capture(
        child.stderr.take().expect("piped stderr"),
        CLI_LIMIT,
        stderr.clone(),
    );
    let mut status_reader = {
        let state = status.clone();
        let stdout = child.stdout.take().expect("piped stdout");
        AbortOnDropHandle::new(tokio::spawn(async move {
            if catch_poll(read_status(stdout, &state)).await.is_err() {
                locked(&state).error = Some("capability reader panicked".into());
            }
        }))
    };
    let mut child_status = None;
    let mut status_done = false;
    let mut stderr_done = false;
    let stop = loop {
        tokio::select! {
            biased;
            result=child.wait(),if child_status.is_none()=>match result {
                Ok(exit)=>child_status=Some(exit),Err(e)=>break Stop::Transport(format!("wait: {e}")),
            },
            result=&mut status_reader,if !status_done=>{
                status_done=true;
                if result.is_err() { break Stop::Panic; }
                if let Some(error)=&locked(&status).error { break Stop::Transport(error.clone()); }
            },
            result=&mut error_reader,if !stderr_done=>{
                stderr_done=true;
                if result.is_err() { locked(&stderr).error=Some("CLI diagnostic reader panicked".into()); }
            },
            ()=cancel.cancelled()=>break Stop::Canceled,
            ()=tokio::time::sleep_until(deadline)=>break Stop::TimedOut,
        }
        if child_status.is_some() && status_done && stderr_done {
            break Stop::Exited;
        }
    };
    if child_status.is_none() {
        let _ = child.start_kill();
        child_status = Some(child.wait().await?);
    }
    if !status_done {
        status_reader.abort();
        let _ = status_reader.await;
    }
    if !stderr_done {
        error_reader.abort();
        let _ = error_reader.await;
    }
    let status = locked(&status).clone();
    let stderr = locked(&stderr).clone();
    Ok(ProbeResult {
        child_status,
        status,
        stderr,
        stop,
    })
}

/// The owner survives a panic while its borrowed supervision future is polled.
/// Capture tasks hold shared buffers; their join results never own evidence.
pub struct OwnedExec {
    child: Child,
    child_status: Option<ExitStatus>,
    writer: Option<AbortOnDropHandle<()>>,
    readers: Vec<AbortOnDropHandle<()>>,
    status_reader: AbortOnDropHandle<()>,
    status_done: bool,
    status: Arc<Mutex<StatusState>>,
    stdout: Arc<Mutex<StreamState>>,
    stderr: Arc<Mutex<StreamState>>,
    cli_stdout: Arc<Mutex<StreamState>>,
    cli_stderr: Arc<Mutex<StreamState>>,
    #[cfg(test)]
    panic_after_status: bool,
}

fn locked<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}

/// Catch each poll, allowing the external owner to reap and settle on panic.
pub async fn catch_poll<F: Future>(future: F) -> Result<F::Output, ()> {
    tokio::pin!(future);
    poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(_) => Poll::Ready(Err(())),
        },
    )
    .await
}

fn pair(parent_shutdown: Shutdown, child_shutdown: Shutdown) -> io::Result<(UnixStream, OwnedFd)> {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: fds has room for the two newly owned descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded and transfers each descriptor once.
    let (parent, child) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let parent = above_stdio(parent)?;
    let child = above_stdio(child)?;
    let parent = StdUnixStream::from(parent);
    let child = StdUnixStream::from(child);
    for fd in [parent.as_raw_fd(), child.as_raw_fd()] {
        // SAFETY: F_SETFD only changes flags of these owned descriptors.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    parent.shutdown(parent_shutdown)?;
    if let Err(e) = child.shutdown(child_shutdown) {
        // Darwin reports ENOTCONN when the peer already closed this direction.
        if e.kind() != io::ErrorKind::NotConnected {
            return Err(e);
        }
    }
    parent.set_nonblocking(true)?;
    Ok((UnixStream::from_std(parent)?, child.into()))
}

fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: duplicate this live owned descriptor, leaving stdio numbers free.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

impl OwnedExec {
    pub fn spawn(bin: &Path, id: &str, spec: &ExecSpec<'_>) -> io::Result<Self> {
        let (status, status_child) = pair(Shutdown::Write, Shutdown::Read)?;
        let (mut stdin, stdin_child) = pair(Shutdown::Read, Shutdown::Write)?;
        let (stdout, stdout_child) = pair(Shutdown::Write, Shutdown::Read)?;
        let (stderr, stderr_child) = pair(Shutdown::Write, Shutdown::Read)?;
        let fds = [
            status_child.as_raw_fd(),
            stdin_child.as_raw_fd(),
            stdout_child.as_raw_fd(),
            stderr_child.as_raw_fd(),
        ];
        let expected_parent = unsafe { libc::getpid() };
        let mut cmd = Command::new(bin);
        cmd.arg("exec")
            .arg("--protocol=1")
            .arg(format!("--status-fd={}", fds[0]))
            .arg(format!("--stdin-fd={}", fds[1]))
            .arg(format!("--stdout-fd={}", fds[2]))
            .arg(format!("--stderr-fd={}", fds[3]))
            .arg(id)
            .arg("--")
            .args(spec.argv)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: only async-signal-safe descriptor/child setup operations run after fork.
        unsafe {
            cmd.pre_exec(move || {
                for fd in fds {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                prepare_child(expected_parent)
            });
        }
        let mut child = cmd.spawn()?;
        drop((status_child, stdin_child, stdout_child, stderr_child));
        let stdout_state = Arc::new(Mutex::new(StreamState::default()));
        let stderr_state = Arc::new(Mutex::new(StreamState::default()));
        let cli_stdout = Arc::new(Mutex::new(StreamState::default()));
        let cli_stderr = Arc::new(Mutex::new(StreamState::default()));
        let readers = vec![
            spawn_capture(stdout, spec.max_output, stdout_state.clone()),
            spawn_capture(stderr, spec.max_output, stderr_state.clone()),
            spawn_capture(
                child.stdout.take().expect("piped stdout"),
                CLI_LIMIT,
                cli_stdout.clone(),
            ),
            spawn_capture(
                child.stderr.take().expect("piped stderr"),
                CLI_LIMIT,
                cli_stderr.clone(),
            ),
        ];
        let data = spec.stdin.to_vec();
        let writer = AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = stdin.write_all(&data).await;
            let _ = stdin.shutdown().await;
        }));
        let status_state = Arc::new(Mutex::new(StatusState::default()));
        let status_reader = {
            let state = status_state.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                if catch_poll(read_status(status, &state)).await.is_err() {
                    locked(&state).error = Some("status reader panicked".into());
                }
            }))
        };
        Ok(Self {
            child,
            child_status: None,
            writer: Some(writer),
            readers,
            status_reader,
            status_done: false,
            status: status_state,
            stdout: stdout_state,
            stderr: stderr_state,
            cli_stdout,
            cli_stderr,
            #[cfg(test)]
            panic_after_status: false,
        })
    }

    pub async fn supervise(&mut self, deadline: Instant, cancel: &CancellationToken) -> Stop {
        match catch_poll(self.drive(deadline, cancel)).await {
            Ok(stop) => stop,
            Err(()) => Stop::Panic,
        }
    }

    async fn drive(&mut self, deadline: Instant, cancel: &CancellationToken) -> Stop {
        loop {
            #[cfg(test)]
            assert!(
                !(self.panic_after_status && self.status_done),
                "injected supervision polling panic"
            );
            tokio::select! {
                biased;
                result = self.child.wait(), if self.child_status.is_none() => match result {
                    Ok(status) => self.child_status = Some(status),
                    Err(e) => return Stop::Transport(format!("wait: {e}")),
                },
                result = &mut self.status_reader, if !self.status_done => {
                    self.status_done = true;
                    if result.is_err() { return Stop::Transport("status task panicked".into()); }
                    if let Some(error) = &locked(&self.status).error { return Stop::Transport(error.clone()); }
                    if self.child_status.is_none() { return Stop::StatusReady; }
                },
                () = cancel.cancelled(), if self.child_status.is_none() => return Stop::Canceled,
                () = tokio::time::sleep_until(deadline) => return if self.child_status.is_some() {
                    Stop::Transport("CLI exited without settling status before deadline".into())
                } else { Stop::TimedOut },
            }
            if self.child_status.is_some() && self.status_done {
                return Stop::Exited;
            }
        }
    }

    pub async fn kill_reap(&mut self) -> io::Result<()> {
        if self.child_status.is_none() {
            let _ = self.child.start_kill();
            self.child_status = Some(self.child.wait().await?);
        }
        if let Some(writer) = self.writer.take() {
            writer.abort();
            let _ = writer.await;
        }
        Ok(())
    }

    pub fn status(&self) -> StatusState {
        locked(&self.status).clone()
    }

    /// After CLI reaping, consume buffered status and EOF before discarding
    /// the reader. A late reply may still prove that cleanup already finished.
    pub async fn settle_status(&mut self) {
        if self.status_done {
            return;
        }
        match tokio::time::timeout(SETTLEMENT_TIMEOUT, &mut self.status_reader).await {
            Ok(result) => {
                if let Err(error) = result {
                    locked(&self.status)
                        .error
                        .get_or_insert_with(|| format!("status task failed: {error}"));
                }
            }
            Err(_) => {
                self.status_reader.abort();
                let _ = (&mut self.status_reader).await;
                locked(&self.status)
                    .error
                    .get_or_insert_with(|| "status settlement timed out before EOF".into());
            }
        }
        self.status_done = true;
    }

    /// Called only after a trusted cleanup reply or the host cleanup barrier.
    pub async fn settle(mut self) -> RawResult {
        self.settle_status().await;
        if let Some(writer) = self.writer.take() {
            writer.abort();
            let _ = writer.await;
        }
        let mut next_reader = 0;
        let settled = tokio::time::timeout(SETTLEMENT_TIMEOUT, async {
            while next_reader < self.readers.len() {
                let _ = (&mut self.readers[next_reader]).await;
                next_reader += 1;
            }
        })
        .await
        .is_ok();
        if !settled {
            for reader in &self.readers[next_reader..] {
                reader.abort();
            }
            for reader in &mut self.readers[next_reader..] {
                let _ = reader.await;
            }
            // EOF/error evidence is checked below, including a task panic.
        }
        for state in [
            &self.stdout,
            &self.stderr,
            &self.cli_stdout,
            &self.cli_stderr,
        ] {
            let mut state = locked(state);
            if !state.eof && state.error.is_none() {
                state.error = Some(
                    if settled {
                        "capture task stopped before EOF"
                    } else {
                        "capture settlement timed out before EOF"
                    }
                    .into(),
                );
            }
        }
        RawResult {
            child_status: self.child_status,
            status: self.status(),
            stdout: locked(&self.stdout).clone(),
            stderr: locked(&self.stderr).clone(),
            cli_stdout: locked(&self.cli_stdout).clone(),
            cli_stderr: locked(&self.cli_stderr).clone(),
        }
    }
}

fn spawn_capture<R: AsyncRead + Unpin + Send + 'static>(
    pipe: R,
    max: usize,
    state: Arc<Mutex<StreamState>>,
) -> AbortOnDropHandle<()> {
    AbortOnDropHandle::new(tokio::spawn(async move {
        if catch_poll(capture(pipe, max, &state)).await.is_err() {
            locked(&state).error = Some("capture reader panicked".into());
        }
    }))
}

async fn capture<R: AsyncRead + Unpin>(mut pipe: R, max: usize, state: &Mutex<StreamState>) {
    let mut buf = [0; 16 * 1024];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => {
                let mut state = locked(state);
                state.eof = true;
                state.captured.total_bytes_known = true;
                return;
            }
            Ok(n) => {
                let mut state = locked(state);
                state.captured.total_bytes += n as u64;
                let room = max.saturating_sub(state.captured.data.len());
                state.captured.truncated |= n > room;
                state.captured.data.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) => {
                locked(state).error = Some(e.to_string());
                return;
            }
        }
    }
}

async fn read_status<R: AsyncRead + Unpin>(mut pipe: R, state: &Mutex<StatusState>) {
    let mut buf = [0; MAX_FRAME + 1];
    let mut frame_deadline = None;
    loop {
        let len = locked(state).bytes.len();
        let read = async { pipe.read(&mut buf[..MAX_FRAME + 1 - len]).await };
        let result = if let Some(deadline) = frame_deadline {
            match tokio::time::timeout_at(deadline, read).await {
                Ok(result) => result,
                Err(_) => {
                    locked(state).error = Some("status frame/EOF deadline expired".into());
                    return;
                }
            }
        } else {
            read.await
        };
        match result {
            Ok(0) => {
                let mut state = locked(state);
                state.eof = true;
                if state.bytes.is_empty() {
                    state.error = Some("missing status frame".into());
                }
                return;
            }
            Ok(n) => {
                frame_deadline.get_or_insert_with(|| Instant::now() + FRAME_TIMEOUT);
                let mut state = locked(state);
                state.bytes.extend_from_slice(&buf[..n]);
                if state.bytes.len() > MAX_FRAME {
                    state.error = Some("oversized/trailing status data".into());
                    return;
                }
            }
            Err(e) => {
                locked(state).error = Some(format!("status read: {e}"));
                return;
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::task::Context;
    use tokio::io::ReadBuf;

    async fn wait_for_cli(
        owner: &mut OwnedExec,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Stop {
        loop {
            let stop = owner.supervise(deadline, cancel).await;
            if !matches!(stop, Stop::StatusReady) {
                return stop;
            }
        }
    }

    pub fn fixture(path: &Path, body: &str) {
        std::fs::write(path, format!(r#"#!/usr/bin/python3
import os,sys,time,signal,socket
CAPS=bytes.fromhex('4b494c4e45584f00010002001d0000001f000000010001000500080000000000302e312e306769742074657374')
EXIT125=bytes.fromhex('4b494c4e45584f000100010018000000010102007d00000000000000000000000000000000000000')
if sys.argv[1]=='capabilities':
    os.write(1,CAPS)
    sys.exit(0)
if sys.argv[1:]==['gc','--help']:
    print('Usage: kiln gc [ID]...')
    sys.exit(0)
fds={{a.split('=')[0]:int(a.split('=')[1]) for a in sys.argv[2:7]}}
STATUS=fds['--status-fd']; IN=fds['--stdin-fd']; OUT=fds['--stdout-fd']; ERR=fds['--stderr-fd']
{body}
"#)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn private_binary_streams_count_all_bytes_and_isolate_cli_diagnostics() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        fixture(
            &bin,
            "data=b'\\x00\\xff'+b'x'*200000\nos.write(OUT,data)\nos.write(ERR,data)\nos.write(1,b'forged stdout')\nos.write(2,EXIT125)\nos.write(STATUS,EXIT125)\nsys.exit(125)",
        );
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(10),
            max_output: 3,
        };
        let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
        assert!(matches!(
            wait_for_cli(&mut owner, spec.deadline, &CancellationToken::new()).await,
            Stop::Exited
        ));
        owner.kill_reap().await.unwrap();
        let raw = owner.settle().await;
        assert_eq!(
            raw.stdout.captured,
            Captured {
                data: b"\0\xffx".to_vec(),
                total_bytes: 200002,
                truncated: true,
                total_bytes_known: true,
            }
        );
        assert_eq!(raw.stderr.captured, raw.stdout.captured);
        assert_eq!(raw.cli_stderr.captured.data, raw.status.bytes);
        assert_eq!(raw.cli_stdout.captured.data, b"forged stdout");
        assert!(raw.stdout.eof && raw.stderr.eof);
    }

    #[tokio::test]
    async fn readers_survive_cleanup_longer_than_generic_drain_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        fixture(
            &bin,
            "os.write(OUT,b'before')\nos.write(STATUS,b'bad')\nos.close(STATUS)\npid=os.fork()\nif pid==0:\n    time.sleep(.5)\n    os.write(OUT,b'after')\n    sys.exit(0)\nsys.exit(125)",
        );
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(10),
            max_output: 1024,
        };
        let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
        assert!(matches!(
            wait_for_cli(&mut owner, spec.deadline, &CancellationToken::new()).await,
            Stop::Exited
        ));
        owner.kill_reap().await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let raw = owner.settle().await;
        assert_eq!(raw.stdout.captured.data, b"beforeafter");
        assert_eq!(raw.status.bytes, b"bad");
    }

    struct FaultReader {
        step: u8,
        panic: bool,
    }
    impl AsyncRead for FaultReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.step == 0 {
                self.step = 1;
                buf.put_slice(b"\0\xffsaved");
                return Poll::Ready(Ok(()));
            }
            assert!(!self.panic, "injected reader polling panic");
            Poll::Ready(Err(io::Error::other("injected read error")))
        }
    }

    #[tokio::test]
    async fn reader_error_and_panic_preserve_evidence() {
        for panic in [false, true] {
            let state = Arc::new(Mutex::new(StreamState::default()));
            spawn_capture(FaultReader { step: 0, panic }, 3, state.clone())
                .await
                .unwrap();
            let state = locked(&state);
            assert_eq!(
                state.captured,
                Captured {
                    data: b"\0\xffs".to_vec(),
                    total_bytes: 7,
                    truncated: true,
                    total_bytes_known: false,
                }
            );
            assert!(state.error.is_some());
            assert!(!state.eof);
        }
    }

    #[tokio::test]
    async fn status_first_byte_starts_frame_timeout_and_requires_eof() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let state = Arc::new(Mutex::new(StatusState::default()));
        let task = tokio::spawn({
            let state = state.clone();
            async move { read_status(reader, &state).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        writer.write_all(b"K").await.unwrap();
        task.await.unwrap();
        assert_eq!(locked(&state).bytes, b"K");
        assert!(locked(&state).error.as_ref().unwrap().contains("deadline"));
    }

    #[tokio::test]
    async fn status_reader_accepts_every_golden_frame_split() {
        for frame in [
            super::super::kiln_protocol::tests::exit125(),
            super::super::kiln_protocol::tests::caps(),
        ] {
            for split in 0..=frame.len() {
                let (reader, mut writer) = UnixStream::pair().unwrap();
                let state = Mutex::new(StatusState::default());
                let ((), ()) = tokio::join!(read_status(reader, &state), async {
                    writer.write_all(&frame[..split]).await.unwrap();
                    tokio::task::yield_now().await;
                    writer.write_all(&frame[split..]).await.unwrap();
                    writer.shutdown().await.unwrap();
                });
                assert_eq!(locked(&state).bytes, frame);
                assert!(locked(&state).eof);
                assert!(locked(&state).error.is_none());
            }
        }
    }

    #[tokio::test]
    async fn supervision_panic_preserves_owner_and_prior_capture_for_reaping() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        fixture(
            &bin,
            "os.write(OUT,b'\\x00\\xffsaved'); os.write(ERR,b'err'); time.sleep(.05); os.write(STATUS,EXIT125); os.close(STATUS); time.sleep(30)",
        );
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(5),
            max_output: 100,
        };
        let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
        let pid = owner.child.id().unwrap();
        owner.panic_after_status = true;
        assert!(matches!(
            wait_for_cli(&mut owner, spec.deadline, &CancellationToken::new()).await,
            Stop::Panic
        ));
        owner.kill_reap().await.unwrap();
        let raw = owner.settle().await;
        assert_eq!(raw.stdout.captured.data, b"\0\xffsaved");
        assert_eq!(raw.stderr.captured.data, b"err");
        // SAFETY: signal zero only checks the already reaped child PID.
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }

    #[tokio::test]
    async fn status_settlement_is_bounded_and_preserves_bytes_when_eof_never_arrives() {
        for prefix in ["K", ""] {
            let tmp = tempfile::tempdir().unwrap();
            let bin = tmp.path().join("kiln");
            fixture(
                &bin,
                &format!(
                    "if os.fork()==0:\n    time.sleep(3)\n    os._exit(0)\nos.write(STATUS,b'{prefix}'); os.write(OUT,b'saved'); time.sleep(30)"
                ),
            );
            let argv = vec!["ignored".into()];
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"",
                deadline: Instant::now() + Duration::from_secs(5),
                max_output: 1024,
            };
            let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while locked(&owner.stdout).captured.data.is_empty() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            assert!(matches!(
                owner
                    .supervise(
                        Instant::now() + Duration::from_millis(20),
                        &CancellationToken::new()
                    )
                    .await,
                Stop::TimedOut
            ));
            owner.kill_reap().await.unwrap();
            let start = Instant::now();
            owner.settle_status().await;
            assert!(start.elapsed() < SETTLEMENT_TIMEOUT + Duration::from_millis(500));
            let status = owner.status();
            assert_eq!(status.bytes, prefix.as_bytes());
            assert!(!status.eof);
            assert!(status.error.is_some());
            let raw = owner.settle().await;
            assert_eq!(raw.stdout.captured.data, b"saved");
        }
    }

    #[tokio::test]
    async fn explicit_settlement_timeout_retains_observed_prefix_and_count() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        fixture(
            &bin,
            "os.write(OUT,b'prefix'); os.write(STATUS,EXIT125); os.close(STATUS)\nif os.fork()==0:\n    time.sleep(3)\n    sys.exit(0)\nsys.exit(125)",
        );
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(5),
            max_output: 3,
        };
        let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
        assert!(matches!(
            wait_for_cli(&mut owner, spec.deadline, &CancellationToken::new()).await,
            Stop::Exited
        ));
        owner.kill_reap().await.unwrap();
        let raw = owner.settle().await;
        assert_eq!(
            raw.stdout.captured,
            Captured {
                data: b"pre".to_vec(),
                total_bytes: 6,
                truncated: true,
                total_bytes_known: false,
            }
        );
        assert!(raw.stdout.error.unwrap().contains("settlement"));
        // Let the fixture's detached holder exit before its temporary directory goes away.
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }

    #[tokio::test]
    async fn owned_exec_recovers_descriptors_in_a_dedicated_child() {
        const CHILD: &str = "KILND_EXEC_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","runtime::kiln_process::tests::owned_exec_recovers_descriptors_in_a_dedicated_child","--nocapture"]).env(CHILD,"1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let count = || {
            std::fs::read_dir(if cfg!(target_os = "linux") {
                "/proc/self/fd"
            } else {
                "/dev/fd"
            })
            .unwrap()
            .count()
        };
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        fixture(
            &bin,
            "os.write(OUT,b'saved'); os.write(STATUS,EXIT125); sys.exit(125)",
        );
        let baseline = count();
        let argv = vec!["ignored".into()];
        for _ in 0..12 {
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"binary\0input",
                deadline: Instant::now() + Duration::from_secs(5),
                max_output: 3,
            };
            let mut owner = OwnedExec::spawn(&bin, "abcd", &spec).unwrap();
            let _ = wait_for_cli(&mut owner, spec.deadline, &CancellationToken::new()).await;
            owner.kill_reap().await.unwrap();
            let raw = owner.settle().await;
            assert_eq!(raw.stdout.captured.total_bytes, 5);
        }
        assert_eq!(count(), baseline, "owned exec leaked descriptors");
    }
}
