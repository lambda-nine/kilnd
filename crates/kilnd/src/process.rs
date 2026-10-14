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
    pub timeout: Duration,
    pub max_output: usize,
}

pub async fn run(req: &Request<'_>, cancel: &CancellationToken) -> io::Result<Outcome> {
    let mut cmd = Command::new(req.program);
    cmd.args(req.args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(if req.stdin.is_empty() { Stdio::null() } else { Stdio::piped() })
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
    let stdout = tokio::spawn(capture(child.stdout.take(), req.max_output, stop_reading.clone()));
    let stderr = tokio::spawn(capture(child.stderr.take(), req.max_output, stop_reading.clone()));
    let writer = child.stdin.take().map(|mut pipe| {
        let data = req.stdin.to_vec();
        // A command that doesn't read its input gets EPIPE here; that's fine.
        tokio::spawn(async move {
            let _ = pipe.write_all(&data).await;
        })
    });

    let finish = tokio::select! {
        status = child.wait() => Finish::Exited(status?),
        () = tokio::time::sleep(req.timeout) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Finish::TimedOut
        }
        () = cancel.cancelled() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Finish::Canceled
        }
    };
    if let Some(writer) = writer {
        writer.abort();
    }

    let drain = async {
        let out = stdout.await.unwrap_or_default();
        let err = stderr.await.unwrap_or_default();
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
    Ok(Outcome { finish, stdout, stderr })
}

/// Keeps the first `max` bytes of a stream and counts the rest, reading to
/// the end so the writer never blocks on a full pipe.
async fn capture<R: AsyncRead + Unpin>(pipe: Option<R>, max: usize, stop: CancellationToken) -> Captured {
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
    use std::time::Instant;

    async fn sh(script: &str, stdin: &[u8], timeout: Duration, max_output: usize) -> Outcome {
        let args = [OsStr::new("-c"), OsStr::new(script)];
        let req = Request { program: Path::new("/bin/sh"), args: &args, stdin, timeout, max_output };
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
        let o = sh("echo out; echo err >&2; exit 3", b"", Duration::from_secs(10), 1024).await;
        assert_eq!(code(&o), Some(3));
        assert_eq!(o.stdout.data, b"out\n");
        assert_eq!(o.stderr.data, b"err\n");
        assert!(!o.stdout.truncated());
    }

    #[tokio::test]
    async fn bounds_output_but_counts_all_of_it() {
        let o = sh("head -c 200000 /dev/zero", b"", Duration::from_secs(10), 1000).await;
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
        let o = sh("echo \"${HOME:-unset}:$PATH\"", b"", Duration::from_secs(10), 1024).await;
        assert_eq!(String::from_utf8_lossy(&o.stdout.data).trim(), format!("unset:{SAFE_PATH}"));
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
            timeout: Duration::from_secs(60),
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
        let o = sh("sleep 30 & echo started", b"", Duration::from_secs(10), 1024).await;
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
}
