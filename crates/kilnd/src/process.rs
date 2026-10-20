//! Runs one host program with an argument vector, bounded output, a timeout
//! and cancellation. Backends use it to drive their CLIs; nothing here goes
//! through a shell.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
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
        });
    }
    if tokio::time::Instant::now() >= req.deadline {
        return Ok(Outcome {
            finish: Finish::TimedOut,
            stdout: Captured::default(),
            stderr: Captured::default(),
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

    let stop_reading = CancellationToken::new();
    // Capture and stdin tasks must never detach from this operation. If the
    // run future is unexpectedly dropped (for example by a backend panic),
    // these wrappers abort the tasks and release their pipe handles.
    let mut stdout = spawn_capture(child.stdout.take(), req.max_output, stop_reading.clone());
    let mut stderr = spawn_capture(child.stderr.take(), req.max_output, stop_reading.clone());
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

    let drain = async {
        let (out, err) = tokio::join!(&mut stdout, &mut stderr);
        let out = out.unwrap_or_default();
        let err = err.unwrap_or_default();
        (out, err)
    };
    tokio::pin!(drain);
    let (stdout, stderr) = tokio::select! {
        both = &mut drain => both,
        () = tokio::time::sleep(DRAIN_GRACE) => {
            stop_reading.cancel();
            drain.await
        }
    };
    let finish = finish?;
    Ok(Outcome {
        finish,
        stdout,
        stderr,
    })
}

fn spawn_capture<R>(
    pipe: Option<R>,
    max: usize,
    stop: CancellationToken,
) -> AbortOnDropHandle<Captured>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    AbortOnDropHandle::new(tokio::spawn(capture(pipe, max, stop)))
}

/// Keeps the first `max` bytes of a stream and counts the rest, reading to
/// the end so the writer never blocks on a full pipe.
async fn capture<R: AsyncRead + Unpin>(
    pipe: Option<R>,
    max: usize,
    stop: CancellationToken,
) -> Captured {
    let mut out = Captured::default();
    let Some(mut pipe) = pipe else { return out };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = tokio::select! {
            // Checked first so a stream that never pauses still stops.
            biased;
            () = stop.cancelled() => break,
            n = pipe.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
        };
        out.total_bytes += n as u64;
        let room = max.saturating_sub(out.data.len());
        out.data.extend_from_slice(&buf[..n.min(room)]);
    }
    out
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
            "sleep 30 & echo started",
            b"",
            Duration::from_secs(10),
            1024,
        )
        .await;
        assert_eq!(code(&o), Some(0));
        assert_eq!(o.stdout.data, b"started\n");
        assert!(start.elapsed() < Duration::from_secs(5));
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
            CancellationToken::new(),
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
}
