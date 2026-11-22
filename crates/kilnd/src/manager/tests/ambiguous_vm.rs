//! Root on the prepared VM: the request floors, the writable-path refusals and
//! `kilnd release-ambiguous` against real kiln, on a private instance (its own state
//! directory, its own in-process helper and its own serving lock), never the node's own
//! kilnd or kilnd-helper.
//!
//! Each step prints one `AMBIG VM` JSON line, the window's record. The test needs an
//! empty `kiln ls` and an empty kiln runs directory to start, and leaves both so. It makes
//! one empty image directory, `ambigvm-empty-<pid>`, kiln's own post-preflight trigger,
//! and removes it by name once the create that needs it has run.
//!
//! The release's process scan must ignore other accounts' processes, whatever they run
//! or are named, and must not fail over one it can't read: the test runs a copy of sleep
//! named kiln, the same through a link named `\xff`, one under a path longer than
//! PATH_MAX and the configured kiln itself as `OTHER`, and two such processes in the live
//! sandbox, through the successful release; root's process under the long path refuses.
//! The audit row's operator uid is the test's login uid when one is set (run it with
//! sudo from a login).
//!
//! A second test, `ambig_vm_preflight_status_over_the_api`, serves the private instance
//! on a private API socket and drives it with the `kilndctl` under test
//! (`KILND_AMBIG_KILNDCTL`) as an ordinary uid, for the status codes a client sees.
//! `KILND_AMBIG_KILND` and `KILND_AMBIG_HELPER` name the `kilnd` and `kilnd-helper`
//! binaries under test.

#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::helper::{ServeLock, ServeLockError};
use crate::runtime::kiln::KilnRuntime;

const KILN: &str = "/usr/local/bin/kiln";
const RUNS: &str = "/var/lib/kiln/runs";
const IMAGES: &str = "/var/lib/kiln/images";
/// kiln's userns `ID_BASE`: sandbox root, the owner of every image directory.
const SANDBOX_ID_BASE: u32 = 2_000_000_000;
/// The private instance's directory: fixed, so the window's cleanup can name it.
const DIR: &str = "/var/tmp/kilnd-ambig-vm";
/// A run directory without `shim.pid`, which `kiln ls` skips.
const STRAY: &str = "ambigvm-stray";
/// The private instance's serving lock, never the node's.
const LOCK: &str = "/var/tmp/kilnd-ambig-vm/helper.lock";
/// A stand-in kiln process: a copy of sleep named kiln, deleted once it runs.
const STAND_IN: &str = "/var/tmp/kilnd-ambig-vm/stand-in";
const OWNER: u32 = 1001;
const OTHER: u32 = 1002;
const ROLE: &str = "KILND_AMBIG_ROLE";

type M = Arc<Manager<KilnRuntime>>;

fn record(step: &str, outcome: Value) {
    println!("AMBIG VM {}", json!({ "step": step, "outcome": outcome }));
}

fn kilnd_bin() -> PathBuf {
    PathBuf::from(std::env::var("KILND_AMBIG_KILND").expect("KILND_AMBIG_KILND"))
}

fn helper_bin() -> PathBuf {
    PathBuf::from(std::env::var("KILND_AMBIG_HELPER").expect("KILND_AMBIG_HELPER"))
}

/// Every process whose exe is named kiln, as `PID EXE ARGV`: the record of what the
/// release's process scan saw.
fn kiln_processes() -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap() {
        let name = entry.unwrap().file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let exe = exe.to_string_lossy().into_owned();
        let base = exe.trim_end_matches(" (deleted)");
        if !base.ends_with("/kiln") {
            continue;
        }
        let argv = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let argv = String::from_utf8_lossy(&argv).replace('\0', " ");
        found.push(format!("{pid} {exe} {}", argv.trim_end()));
    }
    found
}

fn kiln(args: &[&str]) -> std::process::Output {
    Command::new(KILN).args(args).output().unwrap()
}

/// `kiln ls` without its header.
fn kiln_ls() -> Vec<String> {
    let out = kiln(&["ls"]);
    assert!(out.status.success(), "kiln ls: {out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_string)
        .collect()
}

/// kiln's runs directory by its entries, whatever `kiln ls` skips.
fn runs_entries() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(RUNS)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn kiln_state() -> Value {
    json!({ "kiln_ls": kiln_ls(), "runs": runs_entries() })
}

/// Only the live sandbox's run, in kiln's listing and its runs directory.
fn assert_only(step: &str, backend: &str) {
    let listed = kiln_ls();
    assert!(
        listed.len() == 1 && listed[0].starts_with(backend),
        "{step}: kiln ls {listed:?}"
    );
    assert_eq!(runs_entries(), [backend.to_string()], "{step}: runs directory");
}

fn assert_clean(step: &str) {
    assert_eq!(kiln_ls(), Vec::<String>::new(), "{step}: kiln ls");
    assert_eq!(
        runs_entries(),
        Vec::<String>::new(),
        "{step}: runs directory"
    );
}

fn code(e: &Error) -> &'static str {
    match e {
        Error::InvalidArgument(_) => "INVALID_ARGUMENT",
        Error::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
        Error::FailedPrecondition(_) => "FAILED_PRECONDITION",
        Error::NotFound(_) => "NOT_FOUND",
        Error::Backend(_) => "backend",
        _ => "other",
    }
}

/// The kilnd account: the only one the release's private helper serves kiln to, as
/// kilnd-helper does. The private state is its, never the node's own state directory.
fn kilnd_account() -> (u32, u32) {
    let name = std::ffi::CString::new("kilnd").unwrap();
    // SAFETY: name is NUL-terminated; the entry is copied out at once.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    assert!(!pw.is_null(), "no kilnd account");
    // SAFETY: pw is a live passwd entry.
    unsafe { ((*pw).pw_uid, (*pw).pw_gid) }
}

/// The state directory and everything in it to `owner`.
fn chown_state(state: &Path, owner: (u32, u32)) {
    fn walk(path: &Path, owner: (u32, u32)) {
        std::os::unix::fs::lchown(path, Some(owner.0), Some(owner.1)).unwrap();
        if std::fs::symlink_metadata(path).unwrap().is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                walk(&entry.unwrap().path(), owner);
            }
        }
    }
    walk(state, owner);
}

/// A private root helper serving the kiln group to this root process alone, holding the
/// private serving lock as kilnd-helper holds the node's: from before it serves until
/// every request it accepted has settled.
struct Helper {
    stop: CancellationToken,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
    _lock: ServeLock,
}

impl Helper {
    fn start(socket: &Path) -> Self {
        let lock = ServeLock::acquire(Path::new(LOCK)).expect("the private serving lock");
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket).unwrap();
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let stop = CancellationToken::new();
        let served = tokio::spawn(crate::helper::serve_with_groups(
            listener,
            0,
            PathBuf::from(KILN),
            None,
            None,
            stop.clone(),
        ));
        Self {
            stop,
            served,
            _lock: lock,
        }
    }

    async fn stop(self) {
        self.stop.cancel();
        tokio::time::timeout(Duration::from_secs(30), self.served)
            .await
            .expect("the private helper settles")
            .unwrap()
            .unwrap();
    }
}

struct Instance {
    state: PathBuf,
    daemon_socket: PathBuf,
    helper: std::sync::Mutex<Option<Helper>>,
}

impl Instance {
    /// The private instance, started as `main.rs` starts kilnd (without its API), with
    /// its private helper.
    async fn start(&self) -> M {
        let helper = Helper::start(&self.daemon_socket);
        assert!(self.helper.lock().unwrap().replace(helper).is_none());
        let m = Arc::new(Manager::new(
            KilnRuntime::with_helper_uid(self.daemon_socket.clone(), 0),
            Store::open(&self.state).unwrap(),
            Limits::default(),
        ));
        let r = m.reconcile().await.unwrap();
        assert!(r.unmanaged.is_empty() && !r.admission_blocked, "{r:?}");
        m.rebase_expiry_clocks().unwrap();
        m.rebase_create_requests().unwrap();
        m.prune().unwrap();
        m
    }

    /// Stops it: everything it supervises drains, its state lock is released, and its
    /// helper settles and gives up the serving lock.
    async fn stop(&self, m: M) {
        m.begin_shutdown();
        tokio::time::timeout(Duration::from_secs(30), m.drain_operations())
            .await
            .expect("drain");
        let mut m = m;
        for _ in 0..100 {
            match Arc::try_unwrap(m) {
                Ok(manager) => {
                    drop(manager);
                    let helper = self.helper.lock().unwrap().take();
                    helper.expect("the private helper").stop().await;
                    return;
                }
                Err(again) => {
                    m = again;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        panic!("the private instance is still referenced");
    }

    /// `kilnd release-ambiguous` as root against this instance, with its private serving
    /// lock: (exit, stdout, stderr). The command serves kiln to itself.
    async fn release(&self, sandbox: &str, as_uid: Option<u32>) -> (i32, String, String) {
        let mut command = Command::new(kilnd_bin());
        command.args([
            "release-ambiguous",
            "--sandbox",
            sandbox,
            "--reason",
            "VM check: kiln ls and the runs directory are clean after the create",
            "--state-dir",
            self.state.to_str().unwrap(),
            "--helper-lock",
            LOCK,
            "--kiln",
            KILN,
        ]);
        if let Some(uid) = as_uid {
            command.uid(uid).gid(uid);
        }
        let out = tokio::task::spawn_blocking(move || command.output())
            .await
            .unwrap()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )
    }

    /// The release refused with `exit` and its message naming `names`. The charge is
    /// checked by `still_charged` once the step's obstacle is gone: reading it starts the
    /// instance, which needs the state lock and an inventory with no unmanaged run.
    async fn refused(&self, step: &str, sandbox: &str, exit: i32, names: &[&str]) {
        let (rc, out, err) = self.release(sandbox, None).await;
        record(step, json!({ "exit": rc, "stdout": out, "stderr": err }));
        assert_eq!(rc, exit, "{step}: {out} {err}");
        assert!(out.is_empty(), "{step}: {out}");
        for name in names {
            assert!(err.contains(name), "{step}: {err} does not name {name}");
        }
    }

    /// After a refusal, the instance still reserves exactly `charged`.
    async fn still_charged(&self, step: &str, charged: &SandboxResources) {
        let reserved = self.charge_as_root().await;
        record(
            step,
            json!({ "reserved_unchanged": &reserved == charged, "kiln": kiln_state() }),
        );
        assert_eq!(&reserved, charged, "{step}");
    }

    /// The instance's reservations, read by starting it as root and stopping it again.
    async fn charge_as_root(&self) -> SandboxResources {
        let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        let had = std::fs::metadata(&self.state).unwrap();
        chown_state(&self.state, owner);
        let m = self.start().await;
        let reserved = m.health().await.unwrap().node_resources.reserved;
        self.stop(m).await;
        use std::os::unix::fs::MetadataExt as _;
        chown_state(&self.state, (had.uid(), had.gid()));
        reserved
    }
}

async fn reserved(m: &M) -> SandboxResources {
    m.health().await.unwrap().node_resources.reserved
}

fn sh(sandbox_id: &str, script: &str) -> ExecRequest {
    ExecRequest {
        sandbox_id: sandbox_id.into(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        stdin: vec![],
        timeout_ms: 0,
        cwd: String::new(),
        env: vec![],
    }
}

/// Create, one exec, delete: everything released and kiln clean again.
async fn round_trip(m: &M, step: &str, request: CreateRequest, script: &str, expect: &str) {
    let zero = reserved(m).await;
    let sandbox = m.create_owned(request, OWNER).await.unwrap_or_else(|e| {
        record(
            step,
            json!({ "create": format!("{} {e}", code(&e)), "kiln": kiln_state() }),
        );
        panic!("{step}: create refused: {e:?}")
    });
    assert_eq!(sandbox.state, SandboxState::Ready, "{step}");
    let spec = &sandbox.spec;
    let exec = m.exec(sh(&sandbox.id, script)).await.unwrap();
    let stdout = String::from_utf8_lossy(&exec.stdout.data).into_owned();
    let stderr = String::from_utf8_lossy(&exec.stderr.data).into_owned();
    let deleted = m.delete(&sandbox.id).await.unwrap();
    let after = reserved(m).await;
    record(
        step,
        json!({
            "id": sandbox.id, "cpu_millis": spec.cpu_millis, "memory_bytes": spec.memory_bytes,
            "pids": spec.pids, "disk_bytes": spec.disk_bytes, "writable": spec.writable_paths,
            "exec": { "exit": exec.exit_code, "stdout": stdout, "stderr": stderr },
            "delete": format!("{:?}", deleted.state), "released": after == zero,
            "kiln": kiln_state(),
        }),
    );
    assert_eq!(exec.exit_code, Some(0), "{step}: {stderr}");
    assert_eq!(stdout, expect, "{step}");
    assert_eq!(deleted.state, SandboxState::Deleted, "{step}");
    assert_eq!(after, zero, "{step}");
    assert_clean(step);
}

fn paths(path: &str) -> CreateRequest {
    CreateRequest {
        read_only_root: true,
        writable_paths: vec![path.into()],
        ..Default::default()
    }
}

/// The row a failed create names: its message starts `create sandbox sb-…: `.
fn row_named_by(error: &Error) -> String {
    let message = error.to_string();
    let id = message
        .strip_prefix("create sandbox ")
        .and_then(|rest| rest.split_once(": "))
        .map(|(id, _)| id.to_string())
        .unwrap_or_else(|| panic!("no row named: {message}"));
    assert!(crate::model::valid_id("sb", &id), "{message}");
    id
}

/// An image directory with nothing in it, owned by kiln's sandbox ID range (userns
/// `ID_BASE`, the owner of every image), as kiln's create-certainty regressions make it.
/// Named for this process, and removed by that name when dropped, panics included.
struct EmptyImage {
    name: String,
    path: PathBuf,
}

impl EmptyImage {
    fn create() -> Self {
        let name = format!("ambigvm-empty-{}", std::process::id());
        let path = Path::new(IMAGES).join(&name);
        std::fs::create_dir(&path).unwrap();
        let image = Self { name, path };
        std::fs::set_permissions(&image.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::chown(&image.path, Some(SANDBOX_ID_BASE), Some(SANDBOX_ID_BASE))
            .unwrap();
        record(
            "empty image",
            json!({ "name": image.name, "owner": SANDBOX_ID_BASE, "mode": "0755" }),
        );
        image
    }
}

impl Drop for EmptyImage {
    fn drop(&mut self) {
        // rmdir, never a recursive removal: the directory was made empty and kiln's
        // failed setup writes nothing into an image.
        if let Err(e) = std::fs::remove_dir(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("AMBIG could not remove {}: {e}", self.path.display());
        }
    }
}

/// Where `OTHER`'s processes run from: root's, 0755, inside the private directory.
const OTHERS: &str = "/var/tmp/kilnd-ambig-vm/other";
/// 17 nested 250-byte directories: an executable below them has a path longer than
/// PATH_MAX, which the kernel can't render as `/proc/PID/exe` (ENAMETOOLONG).
const DEEP_LEVELS: usize = 17;

/// In the live sandbox, as its root (another account to the host): a script named `\xff`
/// (its command name) that waits, and busybox as `sleep` under a path longer than
/// PATH_MAX, made one relative step at a time. Both detached, so they outlive the exec.
const SANDBOX_HOSTILE: &str = r#"set -e
ff=$(printf '\377')
printf '#!/bin/sh\nsleep 600\n' > "/tmp/$ff"
chmod 755 "/tmp/$ff"
setsid "/tmp/$ff" </dev/null >/dev/null 2>&1 &
d=$(printf "%0250d" 0)
cd -P /tmp
mkdir deep
cd -P deep
i=0
while [ $i -lt 17 ]; do mkdir "$d"; cd -P "$d"; i=$((i+1)); done
cp /bin/busybox bb
ln -s bb sleep
setsid ./sleep 600 </dev/null >/dev/null 2>&1 &
echo planted"#;

fn open_dir_at(at: libc::c_int, name: &std::ffi::CStr) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd as _;
    // SAFETY: a live directory descriptor (or AT_FDCWD), a NUL-terminated name and flags.
    let fd = unsafe {
        libc::openat(
            at,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    assert!(fd >= 0, "open {name:?}: {}", std::io::Error::last_os_error());
    // SAFETY: openat returned a new owned descriptor.
    unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
}

/// A copy of sleep, `x`, at the bottom of [`DEEP_LEVELS`] directories below [`OTHERS`],
/// made one component at a time (no path given to a system call passes PATH_MAX): the
/// descriptor of its directory.
fn deep_sleep() -> std::os::fd::OwnedFd {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    let mut dir = open_dir_at(libc::AT_FDCWD, &std::ffi::CString::new(OTHERS).unwrap());
    let name = std::ffi::CString::new("d".repeat(250)).unwrap();
    for _ in 0..DEEP_LEVELS {
        // SAFETY: a live directory descriptor and a NUL-terminated name.
        let made = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) };
        assert_eq!(made, 0, "mkdirat: {}", std::io::Error::last_os_error());
        dir = open_dir_at(dir.as_raw_fd(), &name);
    }
    // SAFETY: a live directory descriptor, a NUL-terminated name, flags and a mode.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"x".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o755,
        )
    };
    assert!(fd >= 0, "create x: {}", std::io::Error::last_os_error());
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&std::fs::read("/bin/sleep").unwrap()).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// `./x 600` in [`deep_sleep`]'s directory, as `uid` (root if `None`).
fn spawn_deep(dir: &std::os::fd::OwnedFd, uid: Option<u32>) -> std::process::Child {
    use std::os::fd::AsRawFd as _;
    let fd = dir.as_raw_fd();
    let mut command = Command::new("./x");
    command
        .arg("600")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(uid) = uid {
        command.uid(uid).gid(uid);
    }
    // SAFETY: fchdir is async-signal-safe, and the descriptor stays open in the parent
    // until spawn returns.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(fd) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command.spawn().unwrap()
}

/// The configured kiln run by `OTHER` (`kiln ls`), its stdout and stderr a pipe already
/// full: it blocks in its first write, alive and running kiln's image, for as long as
/// the read end (returned) stays open and unread.
fn blocked_kiln_as_other() -> (std::process::Child, std::os::fd::OwnedFd) {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    let mut fds = [0; 2];
    // SAFETY: a valid array of two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
    // SAFETY: pipe2 returned two new owned descriptors.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for chunk in [4096, 1] {
        let bytes = vec![b'x'; chunk];
        // SAFETY: a live descriptor and a buffer of `chunk` bytes.
        while unsafe { libc::write(write.as_raw_fd(), bytes.as_ptr().cast(), chunk) } > 0 {}
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN));
    }
    // SAFETY: fcntl on a live descriptor.
    unsafe {
        let flags = libc::fcntl(write.as_raw_fd(), libc::F_GETFL);
        assert_eq!(libc::fcntl(write.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK), 0);
    }
    let error = write.try_clone().unwrap();
    let child = Command::new(KILN)
        .arg("ls")
        .uid(OTHER)
        .gid(OTHER)
        .stdin(Stdio::null())
        .stdout(Stdio::from(write))
        .stderr(Stdio::from(error))
        .spawn()
        .unwrap();
    (child, read)
}

/// A copy of sleep named kiln in [`OTHERS`].
fn kiln_copy() -> PathBuf {
    Path::new(OTHERS).join("kiln")
}

/// A link named `\xff` to [`kiln_copy`]: a process run through it has that command name.
fn kiln_copy_link() -> PathBuf {
    Path::new(OTHERS).join(std::ffi::OsStr::from_bytes(b"\xff"))
}

/// [`OTHERS`], with [`kiln_copy`] and [`kiln_copy_link`] in it.
fn plant_kiln_copy() {
    std::fs::create_dir(OTHERS).unwrap();
    std::fs::set_permissions(OTHERS, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy("/bin/sleep", kiln_copy()).unwrap();
    std::fs::set_permissions(kiln_copy(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("kiln", kiln_copy_link()).unwrap();
}

/// `OTHER`'s processes, each a child of this test: killed and reaped when dropped.
struct Others {
    children: Vec<(&'static str, std::process::Child)>,
    _pipe: std::os::fd::OwnedFd,
}

impl Others {
    /// A copy of sleep named kiln (security review LOW 1), the same run through a link
    /// named `\xff` (fix review R2), a copy of sleep under a path longer than PATH_MAX
    /// (fix re-review R4) and the configured kiln itself (option (a)), all as `OTHER`.
    fn start(deep: &std::os::fd::OwnedFd) -> Self {
        let (copy, link) = (kiln_copy(), kiln_copy_link());
        let as_other = |program: &Path| {
            Command::new(program)
                .arg("600")
                .uid(OTHER)
                .gid(OTHER)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let (kiln, pipe) = blocked_kiln_as_other();
        let others = Self {
            children: vec![
                ("kiln copy", as_other(&copy)),
                ("kiln copy through a link named \\xff", as_other(&link)),
                ("sleep under a path past PATH_MAX", spawn_deep(deep, Some(OTHER))),
                ("the configured kiln", kiln),
            ],
            _pipe: pipe,
        };
        // Each is exec'd and running: its image is what it was started from.
        std::thread::sleep(Duration::from_secs(1));
        others
    }

    /// Each process: its pid, whether it still runs, its exe link (or the error) and its
    /// command name, as root reads them.
    fn state(&mut self) -> Vec<Value> {
        self.children
            .iter_mut()
            .map(|(what, child)| {
                let pid = child.id();
                let exe = match std::fs::read_link(format!("/proc/{pid}/exe")) {
                    Ok(exe) => exe.to_string_lossy().into_owned(),
                    Err(e) => format!("error: {e}"),
                };
                let comm = std::fs::read(format!("/proc/{pid}/comm")).unwrap_or_default();
                let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
                json!({ "what": what, "pid": pid, "running": child.try_wait().unwrap().is_none(),
                        "exe": exe, "comm": format!("{:?}", String::from_utf8_lossy(&comm)),
                        "wchan": wchan })
            })
            .collect()
    }

    fn all_running(&mut self) -> bool {
        self.children
            .iter_mut()
            .all(|(_, child)| child.try_wait().unwrap().is_none())
    }
}

impl Drop for Others {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// How many processes on the node have the command name `\xff`, and how many an exe
/// link the kernel can't render: the record that the hostile set is in place.
fn hostile_counts() -> (usize, usize) {
    let (mut named, mut long) = (0, 0);
    for entry in std::fs::read_dir("/proc").unwrap() {
        let name = entry.unwrap().file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        if std::fs::read(format!("/proc/{pid}/comm")).is_ok_and(|comm| comm == b"\xff\n") {
            named += 1;
        }
        if std::fs::read_link(format!("/proc/{pid}/exe"))
            .is_err_and(|e| e.raw_os_error() == Some(libc::ENAMETOOLONG))
        {
            long += 1;
        }
    }
    (named, long)
}

/// The audit login uid this test runs under, if a login set one: what a release it
/// runs records as its operator.
fn login_uid() -> Option<u32> {
    let text = std::fs::read_to_string("/proc/self/loginuid").ok()?;
    text.trim().parse().ok().filter(|&uid| uid != u32::MAX)
}

#[test]
#[ignore = "a child role of the ambiguous-create VM test"]
fn ambig_vm_lock_holder_child() {
    if std::env::var(ROLE).as_deref() != Ok("hold") {
        return;
    }
    let state = PathBuf::from(std::env::var("KILND_AMBIG_STATE").unwrap());
    let (uid, gid) = kilnd_account();
    // SAFETY: plain credential calls at the start of a child process, checked.
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setresgid(gid, gid, gid), 0);
        assert_eq!(libc::setresuid(uid, uid, uid), 0);
    }
    // The private instance's own open: its state lock, as kilnd takes it first.
    let _store = Store::open(&state).unwrap();
    println!("AMBIG HOLDING");
    std::io::stdout().flush().unwrap();
    let mut sink = String::new();
    while std::io::stdin().read_line(&mut sink).unwrap() > 0 {}
}

#[test]
#[ignore = "root on the prepared VM: ambiguous-create floors, paths and release"]
fn ambig_vm_floors_paths_and_audited_release() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    assert_clean("start");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(scenario());
}

#[test]
#[ignore = "root on the prepared VM: a kiln preflight refusal's status over the API"]
fn ambig_vm_preflight_status_over_the_api() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    assert_clean("api start");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(api_scenario());
}

fn kilndctl_bin() -> PathBuf {
    PathBuf::from(std::env::var("KILND_AMBIG_KILNDCTL").expect("KILND_AMBIG_KILNDCTL"))
}

/// `kilndctl --socket SOCKET ARGS` as `OTHER`, an ordinary uid with no supplementary
/// groups, in a clean environment: its exit code, stdout and stderr.
async fn ctl(socket: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = tokio::process::Command::new(kilndctl_bin())
        .arg("--socket")
        .arg(socket)
        .args(args)
        .uid(OTHER)
        .gid(OTHER)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).trim().to_string();
    (out.status.code(), text(&out.stdout), text(&out.stderr))
}

/// The private instance behind a private API socket, reached with the branch's kilndctl
/// as an ordinary uid: kiln's preflight refusals (a writable path whose image parent is
/// a symlink, a missing image) are INVALID_ARGUMENT naming an uncharged FAILED row; a
/// keyed one answers OK with that row on the original and its replay alike; and a
/// failure after allocation (the empty image) stays INTERNAL.
async fn api_scenario() {
    let dir = Path::new(DIR);
    std::fs::create_dir(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let instance = Instance {
        state: dir.join("state"),
        daemon_socket: dir.join("helper-daemon.sock"),
        helper: std::sync::Mutex::new(None),
    };
    std::fs::create_dir(&instance.state).unwrap();
    std::fs::set_permissions(&instance.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let api_dir = dir.join("api");
    std::fs::create_dir(&api_dir).unwrap();
    let socket = api_dir.join("kilnd.sock");
    let m = instance.start().await;
    let zero = reserved(&m).await;
    let bound = crate::server::bind(&socket, Some(OTHER)).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(crate::server::serve(
        Arc::clone(&m),
        bound,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    let missing = format!("ambigvm-missing-{}", std::process::id());
    let refusals = [
        (
            "api /var/run/x",
            vec!["--read-only", "--writable", "/var/run/x"],
            "/var/run/x",
        ),
        (
            "api missing image",
            vec!["--image", missing.as_str()],
            missing.as_str(),
        ),
    ];
    let mut refused_ids = Vec::new();
    for (step, extra, names) in &refusals {
        let mut args = vec!["create", "--memory", "64M", "--disk", "64M"];
        args.extend(extra.iter().copied());
        let (rc, out, err) = ctl(&socket, &args).await;
        let id = err
            .strip_prefix("kilndctl: invalidargument: create sandbox ")
            .and_then(|rest| rest.split_once(": "))
            .map(|(id, _)| id.to_string())
            .unwrap_or_default();
        let row = m.get(&id, 0).ok().map(|(row, _)| row);
        record(
            step,
            json!({ "exit": rc, "stdout": out, "stderr": err, "id": id,
                    "state": row.as_ref().map(|r| format!("{:?}", r.state)),
                    "certainty": row.as_ref().map(|r| format!("{:?}", r.create_certainty)),
                    "charged": row.as_ref().map(|r| r.is_charged()),
                    "reserved_zero": reserved(&m).await == zero, "kiln": kiln_state() }),
        );
        assert_ne!(rc, Some(0), "{step}: {err}");
        assert!(out.is_empty(), "{step}: {out}");
        assert!(
            err.starts_with(&format!(
                "kilndctl: invalidargument: create sandbox {id}: kiln create failed (exit status: 124): "
            )) && err.contains(names),
            "{step}: {err}"
        );
        let row = row.unwrap_or_else(|| panic!("{step}: no row {id}"));
        assert_eq!(row.state, SandboxState::Failed, "{step}");
        assert_eq!(
            row.create_certainty,
            CreateCertainty::DefinitelyNotCreated,
            "{step}"
        );
        assert!(!row.is_charged(), "{step}");
        assert_eq!(reserved(&m).await, zero, "{step}");
        assert_clean(step);
        refused_ids.push(id);
    }

    // Keyed: the original and its replay give the same answer, OK with the FAILED row.
    let key = format!("ambigvm-preflight-{}", std::process::id());
    let keyed = [
        "create",
        "--memory",
        "64M",
        "--disk",
        "64M",
        "--read-only",
        "--writable",
        "/var/run/x",
        "--request-id",
        key.as_str(),
    ];
    let first = ctl(&socket, &keyed).await;
    let replay = ctl(&socket, &keyed).await;
    let keyed_row = m.get(&first.1, 0).ok().map(|(row, _)| row);
    record(
        "api keyed /var/run/x",
        json!({ "first": { "exit": first.0, "stdout": first.1, "stderr": first.2 },
                "replay": { "exit": replay.0, "stdout": replay.1, "stderr": replay.2 },
                "state": keyed_row.as_ref().map(|r| format!("{:?}", r.state)),
                "certainty": keyed_row.as_ref().map(|r| format!("{:?}", r.create_certainty)),
                "failure_reason": keyed_row.as_ref().and_then(|r| r.failure_reason.clone()),
                "reserved_zero": reserved(&m).await == zero, "kiln": kiln_state() }),
    );
    assert_eq!(first.0, Some(0), "keyed: {}", first.2);
    assert_eq!(first, replay, "keyed replay");
    let keyed_row = keyed_row.expect("the keyed row");
    assert_eq!(keyed_row.state, SandboxState::Failed);
    assert_eq!(
        keyed_row.create_certainty,
        CreateCertainty::DefinitelyNotCreated
    );
    assert!(
        keyed_row
            .failure_reason
            .as_deref()
            .unwrap_or_default()
            .contains("exit status: 124"),
        "{keyed_row:?}"
    );
    assert_eq!(reserved(&m).await, zero);
    assert_clean("api keyed");

    // After allocation: kiln's empty-image trigger stays INTERNAL (and ambiguous; the
    // private instance's state goes with it below).
    let empty = EmptyImage::create();
    let (rc, out, err) = ctl(
        &socket,
        &[
            "create",
            "--memory",
            "64M",
            "--disk",
            "64M",
            "--image",
            empty.name.as_str(),
        ],
    )
    .await;
    drop(empty);
    record(
        "api empty image",
        json!({ "exit": rc, "stdout": out, "stderr": err, "kiln": kiln_state() }),
    );
    assert_ne!(rc, Some(0), "{err}");
    assert!(
        err.starts_with("kilndctl: internal: create sandbox sb-"),
        "{err}"
    );
    assert!(!err.contains("exit status: 124"), "{err}");
    assert_clean("api empty image");

    for id in refused_ids.iter().chain([&first.1]) {
        let (rc, _, err) = ctl(&socket, &["rm", id]).await;
        assert_eq!(rc, Some(0), "rm {id}: {err}");
    }
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    instance.stop(m).await;
    std::fs::remove_dir_all(dir).unwrap();
    assert_clean("api end");
}

async fn scenario() {
    let dir = Path::new(DIR);
    std::fs::create_dir(dir).unwrap();
    // Readable: the state's opener walks every ancestor as a directory after dropping to
    // the state's owner, as kilnd does under /var/lib. The sockets inside stay 0600.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let instance = Instance {
        state: dir.join("state"),
        daemon_socket: dir.join("helper-daemon.sock"),
        helper: std::sync::Mutex::new(None),
    };
    std::fs::create_dir(&instance.state).unwrap();
    std::fs::set_permissions(&instance.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (kilnd_uid, kilnd_gid) = kilnd_account();

    let m = instance.start().await;
    let zero = reserved(&m).await;
    assert_eq!(zero, SandboxResources::default());

    // 1. Below every floor, and over kiln's own mounts: INVALID_ARGUMENT, nothing
    //    charged, nothing in kiln.
    let below = [
        (
            "cpu_millis 1",
            CreateRequest {
                cpu_millis: 1,
                ..Default::default()
            },
        ),
        (
            "cpu_millis 9",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS - 1,
                ..Default::default()
            },
        ),
        (
            "memory 1 MiB",
            CreateRequest {
                memory_bytes: 1 << 20,
                ..Default::default()
            },
        ),
        (
            "memory floor - 1",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES - 1,
                ..Default::default()
            },
        ),
        (
            "pids 1",
            CreateRequest {
                pids: 1,
                ..Default::default()
            },
        ),
        (
            "pids 15",
            CreateRequest {
                pids: MIN_PIDS - 1,
                ..Default::default()
            },
        ),
        (
            "disk 1",
            CreateRequest {
                disk_bytes: 1,
                ..Default::default()
            },
        ),
        (
            "disk 12288",
            CreateRequest {
                disk_bytes: 12288,
                ..Default::default()
            },
        ),
        (
            "disk floor - 1",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES - 1,
                ..Default::default()
            },
        ),
        ("/proc", paths("/proc")),
        ("/proc/x", paths("/proc/x")),
        ("/sys/x", paths("/sys/x")),
        ("/sys/fs/cgroup/x", paths("/sys/fs/cgroup/x")),
        ("/dev/x", paths("/dev/x")),
    ];
    for (name, request) in below {
        let error = m.create_owned(request, OWNER).await.unwrap_err();
        let rows = m.list(true).unwrap().len();
        let charged = reserved(&m).await;
        record(
            &format!("refused {name}"),
            json!({ "code": code(&error), "message": error.to_string(), "rows": rows,
                    "charged": charged != zero, "kiln": kiln_state() }),
        );
        assert_eq!(code(&error), "INVALID_ARGUMENT", "{name}: {error:?}");
        assert_eq!((rows, charged), (0, zero), "{name}");
        assert_clean(name);
    }

    // 2. Exactly at each floor, then all together: create, one exec, delete.
    let at = [
        (
            "at cpu floor",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS,
                ..Default::default()
            },
        ),
        (
            "at memory floor",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES,
                ..Default::default()
            },
        ),
        (
            "at pids floor",
            CreateRequest {
                pids: MIN_PIDS,
                ..Default::default()
            },
        ),
        (
            "at disk floor",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES,
                ..Default::default()
            },
        ),
        (
            "at every floor",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS,
                memory_bytes: MIN_MEMORY_BYTES,
                pids: MIN_PIDS,
                disk_bytes: MIN_DISK_BYTES,
                ..Default::default()
            },
        ),
    ];
    for (name, request) in at {
        round_trip(&m, name, request, "echo ok", "ok\n").await;
    }
    // /dev/shm is kiln's writable tmpfs: a path under it creates and is writable.
    round_trip(
        &m,
        "/dev/shm/x writable",
        paths("/dev/shm/x"),
        "echo hi > /dev/shm/x/f && cat /dev/shm/x/f",
        "hi\n",
    )
    .await;
    let deleted_id = m.list(true).unwrap()[0].id.clone();

    // 3. A live sandbox of the instance's, which the release must explain (its published
    //    shim, its init and their processes).
    let limits = Limits::default();
    let live = m
        .create_owned(
            CreateRequest {
                memory_bytes: 2 * MIN_MEMORY_BYTES,
                ..Default::default()
            },
            OWNER,
        )
        .await
        .unwrap();
    assert_eq!(live.state, SandboxState::Ready);
    let live_backend = live.backend_id.clone().unwrap();
    let live_charge = reserved(&m).await;
    record(
        "live sandbox",
        json!({ "id": live.id, "backend_id": live_backend, "memory_bytes": live.spec.memory_bytes,
                "kiln": kiln_state(), "kiln_processes": kiln_processes() }),
    );
    // Its own processes whose command name isn't UTF-8 and whose executable's path the
    // kernel can't render (fix review R2, re-review R4): sandbox root is another account
    // to the host, so the release's scan ignores them, through the release in step 5.
    let planted = m.exec(sh(&live.id, SANDBOX_HOSTILE)).await.unwrap();
    record(
        "sandbox hostile processes",
        json!({ "exit": planted.exit_code,
                "stdout": String::from_utf8_lossy(&planted.stdout.data),
                "stderr": String::from_utf8_lossy(&planted.stderr.data) }),
    );
    assert_eq!(
        planted.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&planted.stderr.data)
    );
    // Each create below asks for the rest of the node's memory budget, so a charge it
    // kept would refuse every other uid.
    let ambiguous_memory = limits.max_node_memory_bytes - live.spec.memory_bytes;

    // 3a. A writable path whose parent in the image is a regular file or a symlink: kiln's
    //     create preflight refuses it before allocating (exit 124). INVALID_ARGUMENT naming
    //     a FAILED, definitely-not-created row, nothing charged and nothing in kiln.
    for path in ["/etc/passwd/x", "/var/run/x"] {
        let step = format!("preflight-refused {path}");
        let error = m
            .create_owned(
                CreateRequest {
                    memory_bytes: ambiguous_memory,
                    ..paths(path)
                },
                OWNER,
            )
            .await
            .unwrap_err();
        let id = row_named_by(&error);
        let (row, _) = m.get(&id, 0).unwrap();
        let charged = reserved(&m).await;
        let other = m
            .create_owned(CreateRequest::default(), OTHER)
            .await
            .unwrap();
        let other_exec = m.exec(sh(&other.id, "echo ok")).await.unwrap();
        let other_deleted = m.delete(&other.id).await.unwrap();
        let deleted = m.delete(&row.id).await.unwrap();
        record(
            &step,
            json!({
                "code": code(&error), "message": error.to_string(), "id": row.id,
                "state": format!("{:?}", row.state), "backend_id": row.backend_id,
                "certainty": format!("{:?}", row.create_certainty), "charged": row.is_charged(),
                "reserved_live_only": charged == live_charge,
                "other_uid": { "id": other.id, "state": format!("{:?}", other.state),
                               "exec_exit": other_exec.exit_code,
                               "delete": format!("{:?}", other_deleted.state) },
                "delete": format!("{:?}", deleted.state), "kiln": kiln_state(),
            }),
        );
        assert_eq!(code(&error), "INVALID_ARGUMENT", "{step}: {error:?}");
        let message = error.to_string();
        assert!(
            message.starts_with(&format!(
                "create sandbox {id}: kiln create failed (exit status: 124): "
            )) && message.contains(path),
            "{step}: {message}"
        );
        assert_eq!(
            (row.state, &row.backend_id),
            (SandboxState::Failed, &None),
            "{step}"
        );
        assert_eq!(
            row.create_certainty,
            CreateCertainty::DefinitelyNotCreated,
            "{step}"
        );
        assert!(!row.is_charged(), "{step}");
        assert_eq!(charged, live_charge, "{step}: reservations");
        assert_eq!(other.state, SandboxState::Ready, "{step}");
        assert_eq!(other_exec.exit_code, Some(0), "{step}");
        assert_eq!(other_deleted.state, SandboxState::Deleted, "{step}");
        assert_eq!(deleted.state, SandboxState::Deleted, "{step}");
        assert_eq!(reserved(&m).await, live_charge, "{step}: after");
        assert_only(&step, &live_backend);
    }

    // 3b. kiln's own post-preflight trigger: an empty image directory, owned by the sandbox
    //     ID range as every image is, passes the preflight and fails after `new_id`
    //     (setup finds no /dev). That leaves an ambiguous FAILED row, charged; with the rest
    //     of the node's memory budget it refuses every other uid.
    let empty = EmptyImage::create();
    let error = m
        .create_owned(
            CreateRequest {
                image: empty.name.clone(),
                memory_bytes: ambiguous_memory,
                ..Default::default()
            },
            OWNER,
        )
        .await
        .unwrap_err();
    let (row, _) = m.get(&row_named_by(&error), 0).unwrap();
    let charged = reserved(&m).await;
    let other = m
        .create_owned(CreateRequest::default(), OTHER)
        .await
        .unwrap_err();
    let delete = m.delete(&row.id).await.unwrap_err();
    record(
        "ambiguous empty image",
        json!({
            "image": empty.name, "code": code(&error), "message": error.to_string(), "id": row.id,
            "state": format!("{:?}", row.state), "backend_id": row.backend_id,
            "certainty": format!("{:?}", row.create_certainty), "charged": row.is_charged(),
            "reserved_memory": charged.memory_bytes, "kiln": kiln_state(),
            "other_uid": format!("{} {other}", code(&other)),
            "delete": format!("{} {delete}", code(&delete)),
        }),
    );
    // Only this create needed the image; it goes now, by name, and on any panic before.
    drop(empty);
    assert_eq!(code(&error), "backend", "{error:?}");
    assert!(!error.to_string().contains("exit status: 124"), "{error}");
    assert_eq!(row.state, SandboxState::Failed);
    assert_eq!(row.backend_id, None);
    assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
    assert!(row.is_charged());
    assert_eq!(charged.memory_bytes, limits.max_node_memory_bytes);
    assert_eq!(code(&other), "RESOURCE_EXHAUSTED", "{other:?}");
    assert!(
        delete.to_string().contains("kilnd release-ambiguous"),
        "{delete}"
    );
    assert_eq!(kiln_ls().len(), 1, "only the live sandbox");
    assert_eq!(runs_entries(), std::slice::from_ref(&live_backend), "ambiguous create");

    // 4. With the instance stopped and its state its account's, release-ambiguous
    //    refuses until the node is proved clean.
    instance.stop(m).await;
    chown_state(&instance.state, (kilnd_uid, kilnd_gid));

    let (rc, out, err) = instance.release(&row.id, Some(OTHER)).await;
    record(
        "refused non-root",
        json!({ "exit": rc, "stdout": out, "stderr": err }),
    );
    assert_eq!(rc, 77, "{err}");

    // A helper serving (here the private instance's own, on its private serving lock):
    // the release never starts its proof.
    let serving = Helper::start(&instance.daemon_socket);
    instance
        .refused(
            "refused helper serving",
            &row.id,
            75,
            &["is held", "stop kilnd-helper", LOCK],
        )
        .await;
    serving.stop().await;
    instance
        .still_charged("charged after helper serving", &charged)
        .await;

    // A helper starting while a release holds the fence (taken by the release's own
    // function) refuses to serve and exits, the real binary included.
    let fence = crate::release_ambiguous::take_helper_fence(Path::new(LOCK)).unwrap();
    let in_process = ServeLock::acquire(Path::new(LOCK));
    let refused_helper = Command::new(helper_bin())
        .args(["--serve-lock", LOCK, "--kiln", KILN])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    drop(fence);
    let free_helper = Command::new(helper_bin())
        .args(["--serve-lock", LOCK, "--kiln", KILN])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let refused_err = String::from_utf8_lossy(&refused_helper.stderr).into_owned();
    let free_err = String::from_utf8_lossy(&free_helper.stderr).into_owned();
    record(
        "helper refused while the fence is held",
        json!({ "in_process_held": matches!(in_process, Err(ServeLockError::Held(_))),
                "binary": { "exit": refused_helper.status.code(), "stderr": refused_err },
                "binary_once_free": { "exit": free_helper.status.code(), "stderr": free_err } }),
    );
    assert!(matches!(in_process, Err(ServeLockError::Held(_))), "{in_process:?}");
    assert!(!refused_helper.status.success());
    assert!(
        refused_err.contains("is held") && refused_err.contains("release-ambiguous"),
        "{refused_err}"
    );
    // Once free, the binary gets past the lock: it stops only for want of systemd's socket.
    assert!(!free_helper.status.success());
    assert!(!free_err.contains("is held"), "{free_err}");
    assert!(free_err.contains("LISTEN_PID") || free_err.contains("environment variable"), "{free_err}");

    // A kiln CLI a stopped helper started that is still running, here an exec into the
    // live sandbox: refused naming its pid, until it is done.
    let mut exec = Command::new(KILN)
        .args(["exec", &live_backend, "sleep", "20"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let exec_pid = exec.id().to_string();
    record("surviving kiln cli", json!({ "pid": exec_pid, "kiln_processes": kiln_processes() }));
    instance
        .refused(
            "refused surviving kiln cli",
            &row.id,
            75,
            &[&format!("{exec_pid} /"), "wait for them to finish"],
        )
        .await;
    assert!(exec.wait().unwrap().success());
    instance
        .still_charged("charged after surviving kiln cli", &charged)
        .await;

    // A stand-in for a shim still setting up whose binary has since been replaced: a
    // kiln-named process with no published run, its file deleted under it.
    std::fs::create_dir(STAND_IN).unwrap();
    let stand_in = Path::new(STAND_IN).join("kiln");
    std::fs::copy("/bin/sleep", &stand_in).unwrap();
    let mut shim = Command::new(&stand_in).arg("60").spawn().unwrap();
    std::fs::remove_file(&stand_in).unwrap();
    let shim_pid = shim.id().to_string();
    record("stand-in shim", json!({ "pid": shim_pid, "kiln_processes": kiln_processes() }));
    instance
        .refused(
            "refused stand-in shim",
            &row.id,
            75,
            &[&format!("{shim_pid} {} (deleted)", stand_in.display())],
        )
        .await;
    shim.kill().unwrap();
    shim.wait().unwrap();
    std::fs::remove_dir(STAND_IN).unwrap();
    instance
        .still_charged("charged after stand-in shim", &charged)
        .await;

    // A root process whose executable's path is longer than PATH_MAX: its exe link can't
    // be read, so it is possibly kiln, named with the error (re-review R4).
    // Root's run of a kiln copy through a link named `\xff` counts, its command name read
    // as bytes (fix review R2).
    plant_kiln_copy();
    let mut root_named = Command::new(kiln_copy_link())
        .arg("600")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let comm = std::fs::read(format!("/proc/{}/comm", root_named.id())).unwrap();
    record(
        "root kiln copy named \\xff",
        json!({ "pid": root_named.id(), "comm": format!("{comm:?}") }),
    );
    assert_eq!(comm, b"\xff\n");
    instance
        .refused(
            "refused root's kiln copy named \\xff",
            &row.id,
            75,
            &[&format!("{} {}", root_named.id(), kiln_copy().display())],
        )
        .await;
    root_named.kill().unwrap();
    root_named.wait().unwrap();
    instance
        .still_charged("charged after root's kiln copy named \\xff", &charged)
        .await;

    let deep = deep_sleep();
    let mut root_deep = spawn_deep(&deep, None);
    std::thread::sleep(Duration::from_secs(1));
    let unreadable = std::fs::read_link(format!("/proc/{}/exe", root_deep.id()));
    record(
        "root process under a long path",
        json!({ "pid": root_deep.id(), "exe": format!("{unreadable:?}") }),
    );
    assert_eq!(
        unreadable.unwrap_err().raw_os_error(),
        Some(libc::ENAMETOOLONG)
    );
    instance
        .refused(
            "refused root's unreadable executable",
            &row.id,
            75,
            &[&format!(
                "{} (executable unreadable: File name too long",
                root_deep.id()
            )],
        )
        .await;
    root_deep.kill().unwrap();
    root_deep.wait().unwrap();
    instance
        .still_charged("charged after root's unreadable executable", &charged)
        .await;

    // Another account's processes never refuse the release, whatever they run or are
    // named, and whether or not their executable can be read (option (a), R2, R4). They
    // run through every step below, the successful release included.
    let mut others = Others::start(&deep);
    let (named, long) = hostile_counts();
    record(
        "other accounts' processes",
        json!({ "others": others.state(), "named_xff": named, "exe_too_long": long,
                "kiln_processes": kiln_processes() }),
    );
    assert!(others.all_running(), "{:?}", others.state());
    assert!(named >= 2 && long >= 2, "the sandbox's and OTHER's: {named} {long}");
    // The checkpoint helper's process table reads the same node (fix review, outside its
    // range): no command name fails it.
    let kiln_meta = std::fs::metadata(KILN).unwrap();
    let table = {
        use std::os::unix::fs::MetadataExt as _;
        crate::helper::checkpoint::kiln::process_table((kiln_meta.dev(), kiln_meta.ino()))
    };
    record(
        "checkpoint process table",
        json!({ "ok": table.is_ok(), "error": table.as_ref().err().map(|e| e.to_string()),
                "artifact_readers": table.as_ref().map(Vec::len).ok() }),
    );
    assert!(table.is_ok(), "{table:?}");

    // The instance holds its lock.
    let mut holder = Command::new(std::env::current_exe().unwrap());
    holder
        .args([
            "--ignored",
            "--exact",
            "manager::ambiguous_vm_tests::ambig_vm_lock_holder_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, "hold")
        .env("KILND_AMBIG_STATE", &instance.state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut holder = holder.spawn().unwrap();
    let mut lines = BufReader::new(holder.stdout.take().unwrap()).lines();
    loop {
        let line = lines
            .next()
            .expect("the holder ended before holding")
            .unwrap();
        if line.contains("AMBIG HOLDING") {
            break;
        }
    }
    instance
        .refused(
            "refused lock held",
            &row.id,
            75,
            &["already owned", "kilnd.lock"],
        )
        .await;
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    instance
        .still_charged("charged after lock held", &charged)
        .await;

    // A run kiln lists that no row owns: created by kiln itself, then removed by ID.
    let out = kiln(&[
        "create",
        "--image=alpine",
        "--memory=67108864",
        "--cpus=0.100",
        "--pids=32",
        "--disk=67108864",
        "--net=none",
    ]);
    assert!(out.status.success(), "kiln create: {out:?}");
    let run = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(kiln_ls().iter().any(|l| l.starts_with(&run)), "{run}");
    instance
        .refused("refused unexplained run", &row.id, 69, &[&run, "kiln rm"])
        .await;
    let rm = kiln(&["rm", &run]);
    record(
        "removed unexplained run",
        json!({ "id": run, "rm": rm.status.code(), "kiln": kiln_state() }),
    );
    assert!(rm.status.success(), "{rm:?}");
    assert_only("after kiln rm", &live_backend);
    instance
        .still_charged("charged after unexplained run", &charged)
        .await;

    // A run directory without shim.pid, which kiln ls skips.
    let stray = Path::new(RUNS).join(STRAY);
    std::fs::create_dir(&stray).unwrap();
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(kiln_ls().len(), 1, "only the live sandbox");
    instance
        .refused("refused pid-less run directory", &row.id, 69, &[STRAY])
        .await;
    std::fs::remove_dir(&stray).unwrap();
    assert_only("after the stray directory", &live_backend);
    instance
        .still_charged("charged after pid-less run directory", &charged)
        .await;

    // Not an ambiguous reservation, and no such sandbox.
    instance
        .refused("refused deleted row", &deleted_id, 65, &["not FAILED"])
        .await;
    instance
        .still_charged("charged after deleted row", &charged)
        .await;
    instance
        .refused(
            "refused unknown id",
            "sb-00000000000000ff",
            65,
            &["no such sandbox"],
        )
        .await;
    instance
        .still_charged("charged after unknown id", &charged)
        .await;

    // 5. Proved clean, with the live sandbox's shim and init running and kiln's node
    //    services as they are: released once, with its audit row.
    //    A kiln process of the node's own (its kilnd's helper calls) refuses with 75
    //    and names it, as documented: the operator retries, so the test does, at most
    //    twice more, recording each attempt.
    let mut attempt = 0;
    let (rc, out, err) = loop {
        attempt += 1;
        let before = kiln_processes();
        let (rc, out, err) = instance.release(&row.id, None).await;
        record(
            "released",
            json!({ "attempt": attempt, "exit": rc, "stdout": out, "stderr": err,
                    "kiln_processes": before }),
        );
        if rc != 75 || attempt == 3 {
            break (rc, out, err);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    assert_eq!(rc, 0, "{err}");
    assert!(
        out.starts_with(&format!(
            "released {} owner_uid={OWNER} sandboxes=1 ",
            row.id
        )) && out.contains(&format!(" memory_bytes={ambiguous_memory} ")),
        "{out}"
    );
    let (named, long) = hostile_counts();
    record(
        "released with other accounts' processes running",
        json!({ "others": others.state(), "named_xff": named, "exe_too_long": long }),
    );
    assert!(others.all_running(), "{:?}", others.state());
    assert!(named >= 2 && long >= 2, "{named} {long}");
    instance
        .refused(
            "refused already released",
            &row.id,
            65,
            &["already released"],
        )
        .await;
    instance
        .still_charged("only the live sandbox charged after already released", &live_charge)
        .await;

    // 6. The instance again, as root: nothing charged, one audit row, and every uid
    //    creates; the released row deletes.
    chown_state(&instance.state, (0, 0));
    let m = instance.start().await;
    let audits = m.store.operator_release_count().unwrap();
    let (released, _) = m.get(&row.id, 0).unwrap();
    let after = reserved(&m).await;
    let exec_live = m.exec(sh(&live.id, "echo live")).await.unwrap();
    let deleted_live = m.delete(&live.id).await.unwrap();
    let after_live = reserved(&m).await;
    record(
        "after release",
        json!({ "audit_rows": audits, "state": format!("{:?}", released.state),
                "accounting": format!("{:?}", released.accounting),
                "charged": released.is_charged(), "reserved_live_only": after == live_charge,
                "live_exec_exit": exec_live.exit_code, "live": format!("{:?}", deleted_live.state),
                "reserved_zero": after_live == zero }),
    );
    assert_eq!(audits, 1);
    assert!(!released.is_charged());
    assert_eq!(after, live_charge);
    assert_eq!(exec_live.exit_code, Some(0));
    assert_eq!(deleted_live.state, SandboxState::Deleted);
    assert_eq!(after_live, zero);
    assert_clean("after the live sandbox");
    let sandbox = m
        .create_owned(CreateRequest::default(), OTHER)
        .await
        .unwrap();
    let exec = m.exec(sh(&sandbox.id, "echo ok")).await.unwrap();
    assert_eq!(exec.exit_code, Some(0));
    m.delete(&sandbox.id).await.unwrap();
    let deleted = m.delete(&row.id).await.unwrap();
    record(
        "other uid creates; released row deletes",
        json!({ "other": sandbox.id, "exec_exit": exec.exit_code,
                "released_row": format!("{:?}", deleted.state), "kiln": kiln_state() }),
    );
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(reserved(&m).await, zero);
    assert_clean("end");
    instance.stop(m).await;
    drop(others);

    // The audit row's operator: the login uid when one is set (sudo leaves it as the
    // login set it), else sudo's SUDO_UID, else the uid the command ran as (root).
    let audit = rusqlite::Connection::open_with_flags(
        instance.state.join("kilnd.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let operator: u32 = audit
        .query_row(
            "SELECT operator_uid FROM operator_releases WHERE sandbox_id = ?1",
            [&row.id],
            |r| r.get(0),
        )
        .unwrap();
    drop(audit);
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|uid| uid.parse::<u32>().ok());
    let expected = login_uid().or(sudo_uid).unwrap_or(0);
    record(
        "audit operator uid",
        json!({ "operator_uid": operator, "login_uid": login_uid(), "sudo_uid": sudo_uid }),
    );
    assert_eq!(operator, expected);
    std::fs::remove_dir_all(dir).unwrap();
}
