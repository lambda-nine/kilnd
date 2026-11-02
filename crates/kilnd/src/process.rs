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

/// Capabilities only the Firecracker supervisor's jailer needs: device nodes, chroot and
/// the VMM's bounding-set drop. Every other helper child gives them up, so legacy kiln
/// children and the L/P/M/K workers keep exactly the pre-B4 set.
#[cfg(target_os = "linux")]
pub(crate) const FIRECRACKER_LAUNCH_CAPABILITIES: [u32; 3] = [27, 18, 8]; // MKNOD, SYS_CHROOT, SETPCAP

/// Drops the launch-only capabilities from every set and proves it, failing closed.
///
/// Every `prctl`, `capget` and `capset` result is checked. On success none of the three
/// capabilities is in the effective, permitted, inheritable, ambient or bounding set.
/// One case cannot drop a bounding bit: a process without `CAP_SETPCAP` in its permitted
/// set (an unprivileged test runner), for which the kernel refuses `PR_CAPBSET_DROP`.
/// Such a process holds none of the three in any other set, and it gets
/// `PR_SET_NO_NEW_PRIVS`, verified, so no later exec can raise one from the bounding set.
/// The helper is root with `CAP_SETPCAP`, so it always takes the strict path.
///
/// Capability sets belong to the calling thread. Every caller is a single-threaded child
/// right after fork (a worker before its loop, a backend child before exec), so that thread
/// is the whole process.
///
/// Allocation-free and async-signal-safe: it runs between fork and exec.
#[cfg(target_os = "linux")]
pub(crate) fn drop_firecracker_launch_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    const SETPCAP: u32 = 8;
    let mask: u32 = FIRECRACKER_LAUNCH_CAPABILITIES
        .iter()
        .fold(0, |mask, cap| mask | (1u32 << cap));
    let last = || io::Error::last_os_error();
    let capget = |data: &mut [Data; 2]| -> io::Result<()> {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        // SAFETY: header and two data words are live, correctly sized storage.
        if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
            return Err(last());
        }
        if header.version != VERSION_3 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    };
    let empty = Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let mut data = [empty; 2];
    capget(&mut data)?;
    let can_setpcap = data[0].permitted & (1 << SETPCAP) != 0;
    // The bounding set, CAP_SETPCAP last: dropping a bounding bit needs it.
    let mut inert_bounding = false;
    for cap in FIRECRACKER_LAUNCH_CAPABILITIES {
        // SAFETY: prctl with constant integer arguments.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if present < 0 {
            return Err(last());
        }
        if present == 0 {
            continue;
        }
        // SAFETY: as above.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
            let error = last();
            if error.raw_os_error() == Some(libc::EPERM) && !can_setpcap {
                inert_bounding = true;
                continue;
            }
            return Err(error);
        }
    }
    // Ambient bits, explicitly; clearing inheritable below would also clear them.
    for cap in FIRECRACKER_LAUNCH_CAPABILITIES {
        // SAFETY: as above.
        let rc = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_LOWER as libc::c_ulong,
                cap as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(last());
        }
    }
    data[0].effective &= !mask;
    data[0].permitted &= !mask;
    data[0].inheritable &= !mask;
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    // SAFETY: header and data are live, correctly sized storage.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0 {
        return Err(last());
    }
    if inert_bounding {
        // SAFETY: as above.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last());
        }
    }
    // Verify every set from the kernel, not from what was asked for.
    let mut after = [empty; 2];
    capget(&mut after)?;
    if (after[0].effective | after[0].permitted | after[0].inheritable) & mask != 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    for cap in FIRECRACKER_LAUNCH_CAPABILITIES {
        // SAFETY: as above.
        let ambient = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                cap as libc::c_ulong,
                0,
                0,
            )
        };
        if ambient != 0 {
            return Err(if ambient < 0 {
                last()
            } else {
                io::Error::from_raw_os_error(libc::EPERM)
            });
        }
        // SAFETY: as above.
        let bounding = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if bounding < 0 {
            return Err(last());
        }
        if bounding != 0 && !inert_bounding {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    if inert_bounding {
        // SAFETY: as above.
        let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if nnp != 1 || after[0].permitted & (1 << SETPCAP) != 0 {
            return Err(if nnp < 0 {
                last()
            } else {
                io::Error::from_raw_os_error(libc::EPERM)
            });
        }
    }
    Ok(())
}

/// A helper worker's first act: drop the launch-only capabilities or exit at once,
/// before any worker loop. A failure here never continues with them held.
#[cfg(target_os = "linux")]
pub(crate) fn require_firecracker_launch_capabilities_dropped() {
    if drop_firecracker_launch_capabilities().is_err() {
        // SAFETY: leave without unwinding or running any further worker code.
        unsafe { libc::_exit(LAUNCH_CAPABILITY_EXIT) }
    }
}

/// The exit status of a worker whose capability drop failed.
#[cfg(target_os = "linux")]
pub(crate) const LAUNCH_CAPABILITY_EXIT: i32 = 76;

/// Shared post-fork setup for every backend process.
///
/// # Safety
/// Runs between `fork` and `exec`; keep this limited to async-signal-safe
/// operations and allocation-free error construction.
pub(crate) unsafe fn prepare_child(expected_parent: libc::pid_t) -> io::Result<()> {
    // Rust ignores SIGPIPE, and an embedding shell or service may ignore the
    // standard lifecycle signals. Ignored dispositions survive exec, so give
    // backend programs predictable Unix defaults.
    for signal in [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGPIPE,
    ] {
        // SAFETY: SIG_DFL installs no handler and every listed signal is valid.
        if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // A failed or unverified drop refuses the exec: the child exits without running
        // the backend.
        drop_firecracker_launch_capabilities()?;
        // SAFETY: prctl is async-signal-safe and uses constant arguments.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // PR_SET_PDEATHSIG is not retroactive. If the captured parent died
        // between fork and prctl, refuse to exec an unsupervised backend.
        if unsafe { libc::getppid() } != expected_parent {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = expected_parent;
    Ok(())
}

/// How long to keep reading output after the program exits. Something it
/// left running in the background may hold the pipes open indefinitely.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Serializes descriptor creation with fork where the OS cannot do both atomically.
/// Darwin has no `pipe2` or `SOCK_CLOEXEC`, so std and these adapters create a
/// descriptor and then set close-on-exec. A fork on another thread in between leaks
/// it into that child, which can then hold a capture pipe open past the drain grace,
/// so a backend's real EOF is never observed. Linux, the only production target,
/// creates them atomically and takes no lock. Hold this from creating a child's
/// descriptors through its spawn, and never across an await.
#[doc(hidden)]
pub struct SpawnGuard {
    #[cfg(not(target_os = "linux"))]
    _held: std::sync::MutexGuard<'static, ()>,
}

#[doc(hidden)]
pub fn spawn_guard() -> SpawnGuard {
    #[cfg(not(target_os = "linux"))]
    {
        static SPAWN: Mutex<()> = Mutex::new(());
        SpawnGuard {
            _held: SPAWN.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
    #[cfg(target_os = "linux")]
    SpawnGuard {}
}

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
            stdout: Captured::known_empty(),
            stderr: Captured::known_empty(),
            stdout_completion: CaptureCompletion::Stopped("request canceled before spawn"),
            stderr_completion: CaptureCompletion::Stopped("request canceled before spawn"),
        });
    }
    if tokio::time::Instant::now() >= req.deadline {
        return Ok(Outcome {
            finish: Finish::TimedOut,
            stdout: Captured::known_empty(),
            stderr: Captured::known_empty(),
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
    let expected_parent = unsafe { libc::getpid() };
    // SAFETY: prepare_child is restricted to async-signal-safe operations.
    unsafe {
        cmd.pre_exec(move || prepare_child(expected_parent));
    }
    let mut child = {
        let _guard = spawn_guard();
        cmd.spawn()?
    };

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
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                state.captured.total_bytes_known = true;
                state.completion.get_or_insert(CaptureCompletion::Eof);
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
        state.captured.truncated |= n > room;
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

    /// The child half of the capability-drop regressions: `KILND_CAP_DROP_CASE` names
    /// a fault to inject (or `none`); the child prints what it saw and exits.
    #[cfg(target_os = "linux")]
    const CAP_DROP_CASE: &str = "KILND_CAP_DROP_CASE";

    #[cfg(target_os = "linux")]
    fn capability_masks() -> [(String, u64); 5] {
        // Capability sets are per thread, and libtest runs this on a worker thread.
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].map(|name| {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}:\t")))
                .unwrap();
            (name.to_string(), u64::from_str_radix(value, 16).unwrap())
        })
    }

    #[cfg(target_os = "linux")]
    fn launch_mask() -> u64 {
        FIRECRACKER_LAUNCH_CAPABILITIES
            .iter()
            .fold(0, |mask, cap| mask | (1u64 << cap))
    }

    /// Installs a seccomp filter answering one syscall with `errno` (0 fakes success
    /// without running it). Irreversible: only ever in a dedicated child process.
    #[cfg(target_os = "linux")]
    fn deny_syscall(nr: libc::c_long, errno: u32) {
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *mut SockFilter,
        }
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        let mut filter = [
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: nr as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | errno,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ];
        let program = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: the program outlives the call; the filter applies to this thread.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(libc::prctl(libc::PR_SET_SECCOMP, 2, &program), 0);
        }
    }

    /// Runs one case in a fresh copy of this test binary, so the filter and the dropped
    /// capabilities never touch the test runner. Returns the exit code and stdout.
    #[cfg(target_os = "linux")]
    fn run_capability_case(case: &str) -> (Option<i32>, String) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::tests::capability_drop_child",
                "--include-ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CAP_DROP_CASE, case)
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "a child of the capability-drop regressions, not a test by itself"]
    fn capability_drop_child() {
        let Ok(case) = std::env::var(CAP_DROP_CASE) else {
            return;
        };
        println!("CAPDROP before {:?}", capability_masks());
        match case.as_str() {
            "none" => {}
            "deny_capget" => deny_syscall(libc::SYS_capget, libc::EPERM as u32),
            "deny_capset" => deny_syscall(libc::SYS_capset, libc::EPERM as u32),
            "deny_prctl" => deny_syscall(libc::SYS_prctl, libc::EPERM as u32),
            "fake_capset" => deny_syscall(libc::SYS_capset, 0),
            other => panic!("unknown case {other}"),
        }
        // The worker entry point: it returns only when the drop is proven.
        require_firecracker_launch_capabilities_dropped();
        let masks = capability_masks();
        let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        println!("CAPDROP returned {masks:?} nnp={nnp}");
        // SAFETY: leave without running the rest of the harness in this child.
        unsafe { libc::_exit(0) }
    }

    /// The drop proves itself in every set, as any user. An unprivileged runner cannot
    /// drop bounding bits, so it must come out with no_new_privs instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn launch_capability_drop_is_verified_in_every_set() {
        let (code, stdout) = run_capability_case("none");
        assert_eq!(code, Some(0), "{stdout}");
        let line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("CAPDROP returned "))
            .unwrap_or_else(|| panic!("{stdout}"));
        let mask = launch_mask();
        for name in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let value = line
                .split(&format!("(\"{name}\", "))
                .nth(1)
                .and_then(|rest| rest.split(')').next())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("{name} in {line}"));
            assert_eq!(value & mask, 0, "{name} kept a launch capability: {line}");
        }
        let bounding = line
            .split("(\"CapBnd\", ")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap();
        assert!(
            bounding & mask == 0 || line.ends_with("nnp=1"),
            "bounding bits stayed usable: {line}"
        );
    }

    /// B4 break-it finding 3, fail-closed: with each capability call made to fail (or to
    /// claim success without acting), the worker entry exits before any worker code,
    /// with the launch capabilities never reported dropped. Run as root under the helper
    /// unit's bounding set by scripts/b4-vm-tests.sh; without them the faults are moot.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_worker_capability_drop_fails_closed() {
        let mask = launch_mask();
        let effective = capability_masks()[2].1;
        assert_eq!(effective & mask, mask, "the fixture lacks the B4 launch capabilities");
        for case in ["deny_capget", "deny_capset", "deny_prctl", "fake_capset"] {
            let (code, stdout) = run_capability_case(case);
            assert!(stdout.contains("CAPDROP before"), "{case}: {stdout}");
            assert!(
                !stdout.contains("CAPDROP returned"),
                "{case}: the worker continued: {stdout}"
            );
            assert_eq!(code, Some(LAUNCH_CAPABILITY_EXIT), "{case}: {stdout}");
            eprintln!("B4 evidence: {case} exited {LAUNCH_CAPABILITY_EXIT} before any worker code");
        }
        // And the strict path as root: every set, bounding included, without the bits.
        let (code, stdout) = run_capability_case("none");
        assert_eq!(code, Some(0), "{stdout}");
        let line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("CAPDROP returned "))
            .unwrap();
        assert!(line.ends_with("nnp=0"), "root drops bounding bits itself: {line}");
        for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let value: u64 = line
                .split(&format!("(\"{name}\", "))
                .nth(1)
                .and_then(|rest| rest.split(')').next())
                .and_then(|v| v.parse().ok())
                .unwrap();
            assert_eq!(value & mask, 0, "{name}: {line}");
        }
        eprintln!("B4 evidence: strict drop {line}");
    }

    #[cfg(target_os = "linux")]
    struct IsolatedProcessGroup {
        child: Option<std::process::Child>,
        pgid: libc::pid_t,
    }

    #[cfg(target_os = "linux")]
    impl IsolatedProcessGroup {
        fn spawn(test_name: &str, child_env: &str, fault_env: Option<&str>) -> io::Result<Self> {
            use std::os::unix::process::CommandExt;

            let mut command = std::process::Command::new(std::env::current_exe()?);
            command
                .args(["--exact", test_name, "--nocapture"])
                .env(child_env, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(fault_env) = fault_env {
                command.env(fault_env, "1");
            }
            // SAFETY: setpgid is async-signal-safe and uses constant arguments.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn()?;
            let pgid = child.id() as libc::pid_t;
            Ok(Self {
                child: Some(child),
                pgid,
            })
        }

        fn wait_with_output(mut self, timeout: Duration) -> io::Result<std::process::Output> {
            let deadline = Instant::now() + timeout;
            loop {
                if self.child.as_mut().unwrap().try_wait()?.is_some() {
                    // Kill any descendant that survived a failing assertion before
                    // reading captured pipes, then prove that the group disappeared.
                    unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
                    let output = self.child.take().unwrap().wait_with_output()?;
                    let group_deadline = Instant::now() + Duration::from_secs(1);
                    loop {
                        if unsafe { libc::kill(-self.pgid, 0) } == -1 {
                            let error = io::Error::last_os_error();
                            if error.raw_os_error() == Some(libc::ESRCH) {
                                return Ok(output);
                            }
                            return Err(error);
                        }
                        if Instant::now() >= group_deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "isolated test process group survived cleanup",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "isolated test subprocess exceeded its deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for IsolatedProcessGroup {
        fn drop(&mut self) {
            unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_until(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> io::Result<i16> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe deadline expired",
                ));
            }
            let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
            if result > 0 {
                return Ok(pollfd.revents);
            }
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe deadline expired",
                ));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn reap_until(pid: libc::pid_t, deadline: Instant) -> io::Result<()> {
        loop {
            let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            if result == pid {
                return Ok(());
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child did not exit before its deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "linux")]
    fn close_fds(fds: &[libc::c_int]) {
        for fd in fds {
            if *fd >= 0 {
                unsafe { libc::close(*fd) };
            }
        }
    }

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
        assert!(o.stdout.total_bytes_known);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_death_during_pre_exec_never_releases_an_unsupervised_child() {
        const CHILD: &str = "KILND_PDEATH_RACE_CHILD";
        const FAIL: &str = "KILND_PDEATH_RACE_FAIL_BEFORE_READY";
        const TEST_NAME: &str =
            "process::tests::parent_death_during_pre_exec_never_releases_an_unsupervised_child";
        if std::env::var_os(CHILD).is_none() {
            let output = IsolatedProcessGroup::spawn(TEST_NAME, CHILD, None)
                .unwrap()
                .wait_with_output(Duration::from_secs(5))
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            // An early grandchild failure must close readiness, fail promptly,
            // and leave no paused supervisor or other process-group member.
            let output = IsolatedProcessGroup::spawn(TEST_NAME, CHILD, Some(FAIL))
                .unwrap()
                .wait_with_output(Duration::from_secs(5))
                .unwrap();
            assert!(
                !output.status.success(),
                "fault injection unexpectedly passed"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("grandchild exited before readiness"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let inject_failure = std::env::var_os(FAIL).is_some();

        // Keep the deliberately orphaned grandchild waitable by this isolated
        // test process so neither the passing nor failing path leaks a process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut ready = [-1; 2];
        let mut release = [-1; 2];
        let mut report = [-1; 2];
        for pipe in [&mut ready, &mut release, &mut report] {
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        }

        let supervisor = unsafe { libc::fork() };
        assert!(supervisor >= 0);
        if supervisor == 0 {
            let child = unsafe { libc::fork() };
            if child < 0 {
                close_fds(&[
                    ready[0], ready[1], release[0], release[1], report[0], report[1],
                ]);
                unsafe { libc::_exit(2) };
            }
            if child == 0 {
                close_fds(&[ready[0], release[1], report[0]]);
                if inject_failure {
                    close_fds(&[ready[1], release[0], report[1]]);
                    unsafe { libc::_exit(7) };
                }
                let expected_parent = unsafe { libc::getppid() };
                let pid = unsafe { libc::getpid() };
                if unsafe {
                    libc::write(
                        ready[1],
                        (&pid as *const libc::pid_t).cast(),
                        std::mem::size_of::<libc::pid_t>(),
                    )
                } != std::mem::size_of::<libc::pid_t>() as isize
                {
                    unsafe { libc::_exit(3) };
                }
                close_fds(&[ready[1]]);
                let mut byte = 0u8;
                if unsafe { libc::read(release[0], (&mut byte as *mut u8).cast(), 1) } != 1 {
                    unsafe { libc::_exit(4) };
                }
                close_fds(&[release[0]]);
                if unsafe { prepare_child(expected_parent) }.is_err() {
                    close_fds(&[report[1]]);
                    unsafe { libc::_exit(0) };
                }
                let reported = unsafe {
                    libc::write(
                        report[1],
                        (&pid as *const libc::pid_t).cast(),
                        std::mem::size_of::<libc::pid_t>(),
                    )
                } == std::mem::size_of::<libc::pid_t>() as isize;
                close_fds(&[report[1]]);
                if reported {
                    unsafe { libc::pause() };
                }
                unsafe { libc::_exit(5) };
            }
            close_fds(&[
                ready[0], ready[1], release[0], release[1], report[0], report[1],
            ]);
            unsafe { libc::pause() };
            unsafe { libc::_exit(6) };
        }

        close_fds(&[ready[1], release[0], report[1]]);

        let mut child = 0;
        let ready_events = poll_until(
            ready[0],
            libc::POLLIN | libc::POLLHUP,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert!(
            ready_events & libc::POLLIN != 0,
            "grandchild exited before readiness"
        );
        assert_eq!(
            unsafe {
                libc::read(
                    ready[0],
                    (&mut child as *mut libc::pid_t).cast(),
                    std::mem::size_of::<libc::pid_t>(),
                )
            },
            std::mem::size_of::<libc::pid_t>() as isize
        );
        close_fds(&[ready[0]]);
        assert_eq!(unsafe { libc::kill(supervisor, libc::SIGKILL) }, 0);
        assert_eq!(
            unsafe { libc::waitpid(supervisor, std::ptr::null_mut(), 0) },
            supervisor
        );
        assert_eq!(
            unsafe { libc::write(release[1], b"x".as_ptr().cast(), 1) },
            1
        );
        close_fds(&[release[1]]);

        let report_events = poll_until(
            report[0],
            libc::POLLIN | libc::POLLHUP,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let survived = report_events & libc::POLLIN != 0;
        close_fds(&[report[0]]);
        if survived {
            unsafe { libc::kill(child, libc::SIGKILL) };
        }
        if let Err(error) = reap_until(child, Instant::now() + Duration::from_secs(1)) {
            unsafe { libc::kill(child, libc::SIGKILL) };
            let _ = reap_until(child, Instant::now() + Duration::from_secs(1));
            panic!("failed to reap grandchild: {error}");
        }
        assert!(
            !survived,
            "child continued after its parent died before PR_SET_PDEATHSIG"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_setup_restores_default_signal_dispositions() {
        const CHILD: &str = "KILND_SIGNAL_DISPOSITION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::tests::child_setup_restores_default_signal_dispositions",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        for signal in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGPIPE,
        ] {
            assert_ne!(
                unsafe { libc::signal(signal, libc::SIG_IGN) },
                libc::SIG_ERR
            );
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                let parent = unsafe { libc::getppid() };
                if unsafe { prepare_child(parent) }.is_err() {
                    unsafe { libc::_exit(2) };
                }
                unsafe { libc::raise(signal) };
                unsafe { libc::_exit(3) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), signal);
        }
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
        assert!(!o.stdout.truncated());
        assert!(!o.stdout.total_bytes_known);
        assert!(!o.stderr.total_bytes_known);
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
                    total_bytes: 7,
                    truncated: true,
                    total_bytes_known: false,
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
                    total_bytes: 7,
                    truncated: true,
                    total_bytes_known: false,
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
                    total_bytes: 3,
                    truncated: false,
                    total_bytes_known: true,
                },
                CaptureCompletion::Eof
            )
        );
        assert_eq!(
            stderr.evidence(),
            (
                Captured {
                    data: b"err".to_vec(),
                    total_bytes: 3,
                    truncated: false,
                    total_bytes_known: true,
                },
                CaptureCompletion::Eof
            )
        );
    }
}
