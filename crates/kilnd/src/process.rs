//! Runs one host program with an argument vector, bounded output, a timeout
//! and cancellation. Backends use it to drive their CLIs; nothing here goes
//! through a shell.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::model::Captured;

/// PATH for child processes. The environment is otherwise cleared so a
/// caller's variables never reach the backend.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How long to keep reading output after the program exits. Something it
/// left running in the background may hold the pipes open indefinitely.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub enum Finish {
    Exited(ExitStatus),
    TimedOut,
    Canceled,
}

#[derive(Debug)]
pub struct Outcome {
    pub finish: Finish,
    pub stdout: Captured,
    pub stderr: Captured,
    pub(crate) stdout_completion: CaptureCompletion,
    pub(crate) stderr_completion: CaptureCompletion,
}

/// Internal control-command evidence; this does not change public output semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CaptureCompletion {
    Eof,
    ReadError(String),
    TaskFailed(String),
    Stopped(&'static str),
}

#[derive(Default)]
struct CaptureState {
    captured: Captured,
    completion: Option<CaptureCompletion>,
}

struct CaptureTask {
    task: AbortOnDropHandle<()>,
    state: Arc<Mutex<CaptureState>>,
    joined: bool,
}

impl CaptureTask {
    async fn join(&mut self) {
        if self.joined {
            return;
        }
        let result = (&mut self.task).await;
        self.joined = true;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Err(error)
                if error.is_cancelled()
                    && matches!(state.completion, Some(CaptureCompletion::Stopped(_))) => {}
            Err(error) => {
                let prior = state
                    .completion
                    .as_ref()
                    .map(|completion| format!("; prior capture completion: {completion:?}"))
                    .unwrap_or_default();
                state.completion = Some(CaptureCompletion::TaskFailed(format!("{error}{prior}")));
            }
            Ok(()) if state.completion.is_none() => {
                state.completion = Some(CaptureCompletion::TaskFailed(
                    "capture task ended without EOF or an error".into(),
                ))
            }
            Ok(()) => {}
        }
    }

    async fn stop(&mut self, reason: &'static str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .completion
            .get_or_insert(CaptureCompletion::Stopped(reason));
        if !self.joined {
            self.task.abort();
        }
        self.join().await;
    }

    fn evidence(&self) -> (Captured, CaptureCompletion) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (
            state.captured.clone(),
            state.completion.clone().unwrap_or_else(|| {
                CaptureCompletion::TaskFailed("capture task was not settled".into())
            }),
        )
    }
}

pub struct Request<'a> {
    pub program: &'a Path,
    pub args: &'a [&'a OsStr],
    pub stdin: &'a [u8],
    pub deadline: tokio::time::Instant,
    pub max_output: usize,
}

pub async fn run(req: &Request<'_>, cancel: &CancellationToken) -> io::Result<Outcome> {
    if cancel.is_cancelled() {
        return Ok(Outcome {
            finish: Finish::Canceled,
            stdout: Captured::default(),
            stderr: Captured::default(),
            stdout_completion: CaptureCompletion::Stopped("request canceled before spawn"),
            stderr_completion: CaptureCompletion::Stopped("request canceled before spawn"),
        });
    }
    if tokio::time::Instant::now() >= req.deadline {
        return Ok(Outcome {
            finish: Finish::TimedOut,
            stdout: Captured::default(),
            stderr: Captured::default(),
            stdout_completion: CaptureCompletion::Stopped(
                "execution deadline expired before spawn",
            ),
            stderr_completion: CaptureCompletion::Stopped(
                "execution deadline expired before spawn",
            ),
        });
    }
    let mut cmd = Command::new(req.program);
    cmd.args(req.args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(if req.stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    // SAFETY: prctl is async-signal-safe, and the closure touches nothing
    // else between fork and exec.
    unsafe {
        // If kilnd dies, its backend clients die too instead of running on
        // unsupervised. kilnd runs on a current-thread runtime, so the thread
        // that forks lives as long as the daemon.
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;

    // Capture and stdin tasks must never detach from this operation. If the
    // run future is unexpectedly dropped (for example by a backend panic),
    // these wrappers abort the tasks and release their pipe handles.
    let mut stdout = spawn_capture(child.stdout.take(), req.max_output);
    let mut stderr = spawn_capture(child.stderr.take(), req.max_output);
    let writer = child.stdin.take().map(|mut pipe| {
        let data = req.stdin.to_vec();
        // A command that doesn't read its input gets EPIPE here; that's fine.
        AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = pipe.write_all(&data).await;
        }))
    });

    let finish = tokio::select! {
        status = child.wait() => status.map(Finish::Exited),
        () = tokio::time::sleep_until(req.deadline) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Ok(Finish::TimedOut)
        }
        () = cancel.cancelled() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Ok(Finish::Canceled)
        }
    };
    if let Some(mut writer) = writer {
        writer.abort();
        let _ = (&mut writer).await;
    }

    drain_captures(&mut stdout, &mut stderr, req.deadline, cancel).await;
    let (stdout, stdout_completion) = stdout.evidence();
    let (stderr, stderr_completion) = stderr.evidence();
    let finish = finish?;
    Ok(Outcome {
        finish,
        stdout,
        stderr,
        stdout_completion,
        stderr_completion,
    })
}

async fn drain_captures(
    stdout: &mut CaptureTask,
    stderr: &mut CaptureTask,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) {
    let stopped = {
        let drain = async {
            tokio::join!(stdout.join(), stderr.join());
        };
        tokio::pin!(drain);
        tokio::select! {
            biased;
            ()=&mut drain=>None,
            ()=cancel.cancelled()=>Some("request canceled during output drainage"),
            ()=tokio::time::sleep_until(deadline)=>Some("execution deadline expired during output drainage"),
            ()=tokio::time::sleep(DRAIN_GRACE)=>Some("250ms output drain grace expired"),
        }
    };
    if let Some(reason) = stopped {
        tokio::join!(stdout.stop(reason), stderr.stop(reason));
    }
}

fn spawn_capture<R>(pipe: Option<R>, max: usize) -> CaptureTask
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let state = Arc::new(Mutex::new(CaptureState::default()));
    let task = {
        let state = state.clone();
        AbortOnDropHandle::new(tokio::spawn(async move {
            capture(pipe, max, &state).await;
        }))
    };
    CaptureTask {
        task,
        state,
        joined: false,
    }
}

/// Keeps the first `max` bytes of a stream and counts the rest, reading to
/// the end so the writer never blocks on a full pipe.
async fn capture<R: AsyncRead + Unpin>(pipe: Option<R>, max: usize, state: &Mutex<CaptureState>) {
    let Some(mut pipe) = pipe else {
        state.lock().unwrap_or_else(|e| e.into_inner()).completion =
            Some(CaptureCompletion::Stopped("capture pipe unavailable"));
        return;
    };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match pipe.read(&mut buf).await {
            Ok(0) => {
                state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .completion
                    .get_or_insert(CaptureCompletion::Eof);
                return;
            }
            Ok(n) => n,
            Err(error) => {
                // An observed read error retains its text even if a forced
                // stop raced with this poll on another executor thread.
                state.lock().unwrap_or_else(|e| e.into_inner()).completion =
                    Some(CaptureCompletion::ReadError(error.to_string()));
                return;
            }
        };
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.captured.total_bytes += n as u64;
        let room = max.saturating_sub(state.captured.data.len());
        state.captured.data.extend_from_slice(&buf[..n.min(room)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use std::time::Instant;
    use tokio::io::{AsyncRead, ReadBuf};

    struct DropReader {
        inner: tokio::io::DuplexStream,
        dropped: Arc<AtomicBool>,
    }

    impl AsyncRead for DropReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl Drop for DropReader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    async fn sh(script: &str, stdin: &[u8], timeout: Duration, max_output: usize) -> Outcome {
        let args = [OsStr::new("-c"), OsStr::new(script)];
        let req = Request {
            program: Path::new("/bin/sh"),
            args: &args,
            stdin,
            deadline: tokio::time::Instant::now() + timeout,
            max_output,
        };
        run(&req, &CancellationToken::new()).await.unwrap()
    }

    fn code(o: &Outcome) -> Option<i32> {
        match o.finish {
            Finish::Exited(s) => s.code(),
            _ => None,
        }
    }

    #[tokio::test]
    async fn captures_output_and_exit_code() {
        let o = sh(
            "echo out; echo err >&2; exit 3",
            b"",
            Duration::from_secs(10),
            1024,
        )
        .await;
        assert_eq!(code(&o), Some(3));
        assert_eq!(o.stdout.data, b"out\n");
        assert_eq!(o.stderr.data, b"err\n");
        assert!(!o.stdout.truncated());
        assert_eq!(o.stdout_completion, CaptureCompletion::Eof);
        assert_eq!(o.stderr_completion, CaptureCompletion::Eof);
    }

    #[tokio::test]
    async fn an_expired_absolute_deadline_is_not_restarted_at_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("spawned");
        let script = format!("touch '{}'", marker.display());
        let args = [OsStr::new("-c"), OsStr::new(&script)];
        let req = Request {
            program: Path::new("/bin/sh"),
            args: &args,
            stdin: b"",
            deadline: tokio::time::Instant::now() - Duration::from_secs(1),
            max_output: 10,
        };
        let outcome =
            tokio::time::timeout(Duration::from_secs(5), run(&req, &CancellationToken::new()))
                .await
                .expect("expired deadline restarted")
                .unwrap();
        assert!(matches!(outcome.finish, Finish::TimedOut));
        assert!(
            !marker.exists(),
            "an already-expired request produced a side effect"
        );
    }

    #[tokio::test]
    async fn bounds_output_but_counts_all_of_it() {
        let o = sh(
            "head -c 200000 /dev/zero",
            b"",
            Duration::from_secs(10),
            1000,
        )
        .await;
        assert_eq!(code(&o), Some(0));
        assert_eq!(o.stdout.data.len(), 1000);
        assert_eq!(o.stdout.total_bytes, 200_000);
        assert!(o.stdout.truncated());
    }

    #[tokio::test]
    async fn passes_stdin() {
        let o = sh("cat", b"hello", Duration::from_secs(10), 1024).await;
        assert_eq!(o.stdout.data, b"hello");
    }

    #[tokio::test]
    async fn clears_the_environment() {
        let o = sh(
            "echo \"${HOME:-unset}:$PATH\"",
            b"",
            Duration::from_secs(10),
            1024,
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&o.stdout.data).trim(),
            format!("unset:{SAFE_PATH}")
        );
    }

    #[tokio::test]
    async fn times_out_and_kills() {
        let start = Instant::now();
        let o = sh("sleep 30", b"", Duration::from_millis(200), 1024).await;
        assert!(matches!(o.finish, Finish::TimedOut));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn cancels() {
        let cancel = CancellationToken::new();
        let args = [OsStr::new("30")];
        let req = Request {
            program: Path::new("/bin/sleep"),
            args: &args,
            stdin: b"",
            deadline: tokio::time::Instant::now() + Duration::from_secs(60),
            max_output: 1024,
        };
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c.cancel();
        });
        let o = run(&req, &cancel).await.unwrap();
        assert!(matches!(o.finish, Finish::Canceled));
    }

    #[tokio::test]
    async fn background_process_holding_pipes_does_not_hang() {
        let start = Instant::now();
        let o = sh(
            "sleep 0.8 & echo started",
            b"",
            Duration::from_secs(10),
            1024,
        )
        .await;
        assert_eq!(code(&o), Some(0));
        assert_eq!(o.stdout.data, b"started\n");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(
            o.stdout_completion,
            CaptureCompletion::Stopped("250ms output drain grace expired")
        );
        assert_eq!(
            o.stderr_completion,
            CaptureCompletion::Stopped("250ms output drain grace expired")
        );
        // Let the test-only inherited pipe holder finish before the test ends.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn command_ignoring_large_stdin_finishes() {
        let input = vec![b'x'; 1 << 20];
        let o = sh("exit 0", &input, Duration::from_secs(10), 1024).await;
        assert_eq!(code(&o), Some(0));
    }

    #[tokio::test]
    async fn dropping_capture_owner_aborts_the_task_and_releases_its_pipe() {
        let (reader, _writer) = tokio::io::duplex(64);
        let dropped = Arc::new(AtomicBool::new(false));
        let task = spawn_capture(
            Some(DropReader {
                inner: reader,
                dropped: dropped.clone(),
            }),
            1024,
        );
        tokio::task::yield_now().await;
        drop(task);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted capture task retained its pipe");
    }

    #[tokio::test]
    async fn a_pre_canceled_request_never_spawns_the_program() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("spawned");
        let script = format!("touch '{}'", marker.display());
        let args = [OsStr::new("-c"), OsStr::new(&script)];
        let req = Request {
            program: Path::new("/bin/sh"),
            args: &args,
            stdin: b"",
            deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            max_output: 1024,
        };
        let cancel = CancellationToken::new();
        cancel.cancel();

        let outcome = run(&req, &cancel).await.unwrap();
        assert!(matches!(outcome.finish, Finish::Canceled));
        assert!(
            !marker.exists(),
            "pre-canceled process produced a side effect"
        );
    }

    struct FaultReader {
        first: bool,
        panic: bool,
    }

    impl AsyncRead for FaultReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.first {
                self.first = false;
                buf.put_slice(b"\0\xffsaved");
                return Poll::Ready(Ok(()));
            }
            assert!(!self.panic, "injected capture polling panic");
            Poll::Ready(Err(io::Error::other("injected capture read failure")))
        }
    }

    #[tokio::test]
    async fn read_errors_and_task_panics_retain_prefix_counts_and_failure_evidence() {
        for panic in [false, true] {
            let mut reader = spawn_capture(Some(FaultReader { first: true, panic }), 3);
            reader.join().await;
            let (captured, completion) = reader.evidence();
            assert_eq!(
                captured,
                Captured {
                    data: b"\0\xffs".to_vec(),
                    total_bytes: 7
                }
            );
            if panic {
                assert!(
                    matches!(completion,CaptureCompletion::TaskFailed(ref error) if error.contains("injected capture polling panic"))
                );
            } else {
                assert_eq!(
                    completion,
                    CaptureCompletion::ReadError("injected capture read failure".into())
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drain_grace_keeps_partial_evidence_and_peer_eof_distinct() {
        let (reader, mut writer) = tokio::io::duplex(64);
        writer.write_all(b"\0\xffsaved").await.unwrap();
        let mut stdout = spawn_capture(Some(reader), 3);
        let mut stderr = spawn_capture(Some(&b""[..]), 3);
        let start = tokio::time::Instant::now();
        drain_captures(
            &mut stdout,
            &mut stderr,
            start + Duration::from_secs(10),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(start.elapsed(), DRAIN_GRACE);
        assert_eq!(
            stdout.evidence(),
            (
                Captured {
                    data: b"\0\xffs".to_vec(),
                    total_bytes: 7
                },
                CaptureCompletion::Stopped("250ms output drain grace expired")
            )
        );
        assert_eq!(stderr.evidence().1, CaptureCompletion::Eof);
    }

    #[tokio::test(start_paused = true)]
    async fn post_child_drain_retains_original_expired_deadline_without_new_grace() {
        let (reader, _writer) = tokio::io::duplex(64);
        let mut stdout = spawn_capture(Some(reader), 3);
        let mut stderr = spawn_capture(Some(&b""[..]), 3);
        stderr.join().await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        tokio::time::advance(Duration::from_millis(100)).await;
        let start = tokio::time::Instant::now();
        drain_captures(
            &mut stdout,
            &mut stderr,
            deadline,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(
            stdout.evidence().1,
            CaptureCompletion::Stopped("execution deadline expired during output drainage")
        );
        assert_eq!(stderr.evidence().1, CaptureCompletion::Eof);
    }

    #[tokio::test(start_paused = true)]
    async fn post_child_drain_cancellation_precedes_expired_deadline() {
        let (reader, _writer) = tokio::io::duplex(64);
        let mut stdout = spawn_capture(Some(reader), 3);
        let mut stderr = spawn_capture(Some(&b""[..]), 3);
        stderr.join().await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let start = tokio::time::Instant::now();
        drain_captures(&mut stdout, &mut stderr, start, &cancel).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(
            stdout.evidence().1,
            CaptureCompletion::Stopped("request canceled during output drainage")
        );
        assert_eq!(stderr.evidence().1, CaptureCompletion::Eof);
    }

    #[tokio::test(start_paused = true)]
    async fn completed_capture_precedes_simultaneous_cancellation_and_deadline() {
        let mut stdout = spawn_capture(Some(&b"out"[..]), 3);
        let mut stderr = spawn_capture(Some(&b"err"[..]), 3);
        while !stdout.task.is_finished() || !stderr.task.is_finished() {
            tokio::task::yield_now().await;
        }
        let cancel = CancellationToken::new();
        cancel.cancel();
        let deadline = tokio::time::Instant::now();
        drain_captures(&mut stdout, &mut stderr, deadline, &cancel).await;
        assert_eq!(
            stdout.evidence(),
            (
                Captured {
                    data: b"out".to_vec(),
                    total_bytes: 3
                },
                CaptureCompletion::Eof
            )
        );
        assert_eq!(
            stderr.evidence(),
            (
                Captured {
                    data: b"err".to_vec(),
                    total_bytes: 3
                },
                CaptureCompletion::Eof
            )
        );
    }
}
