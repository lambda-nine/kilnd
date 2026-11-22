//! The root side of `kilnd release-ambiguous` (docs/setup.md, "Releasing an ambiguous
//! reservation"): what it needs as root before it gives root up, the root half that stays
//! behind, and how it reports. The proof and the release are
//! [`crate::manager::Manager::release_ambiguous`].
//!
//! As root the command takes the helper's serving lock ([`take_helper_fence`]), so no
//! kilnd-helper serves until it ends, and opens kiln's runs directory. It then forks.
//! The child gives up root for the state directory's account and runs the proof against
//! the parent, which keeps root and the lock and is the only helper on the node: it
//! serves the helper protocol's kiln group on a private abstract socket to that account
//! alone ([`serve_root_half`]), and answers the proof's process scans
//! ([`unexplained_kiln_processes`]). The child inherits the lock's descriptor, so the
//! fence holds until the commit even if the parent dies first.

use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::helper::{ServeLock, ServeLockError};
use crate::manager::{KilnProcesses, ReleaseNode, ReleaseProved, ReleaseRefusal};

/// kiln's runs directory, where every run, persistent or one-shot, has its directory
/// (kiln `runtime/src/persistent.rs:24`, `runtime/src/container.rs:769`). The helper's
/// checkpoint group uses the same path.
pub const KILN_RUNS: &str = crate::helper::checkpoint::kiln::KILN_RUNS;

/// Released.
pub const EXIT_RELEASED: u8 = 0;
/// A malformed argument (EX_USAGE).
pub const EXIT_USAGE: u8 = 64;
/// The sandbox is unknown or is not a charged ambiguous reservation (EX_DATAERR).
pub const EXIT_INELIGIBLE: u8 = 65;
/// The node is not proved clean: an unexplained run, a listing error or deadline, a
/// blocked reconciliation or an unreadable runs directory (EX_UNAVAILABLE).
pub const EXIT_NOT_PROVED: u8 = 69;
/// Something is still at work: kilnd (or anything else) holds this instance's state
/// lock, kilnd-helper (or another release) holds the helper's serving lock, or a kiln
/// process could still publish a run (EX_TEMPFAIL). Retry once it has stopped.
pub const EXIT_BUSY: u8 = 75;
/// Not run as root (EX_NOPERM).
pub const EXIT_NOT_ROOT: u8 = 77;

/// The exit code for a refusal.
pub fn refusal_exit(refusal: &ReleaseRefusal) -> u8 {
    match refusal {
        ReleaseRefusal::NoSandbox | ReleaseRefusal::Ineligible(_) => EXIT_INELIGIBLE,
        ReleaseRefusal::Inventory(_)
        | ReleaseRefusal::Blocked { .. }
        | ReleaseRefusal::UnexplainedRuns(_)
        | ReleaseRefusal::UnexplainedRunDirectories(_) => EXIT_NOT_PROVED,
        ReleaseRefusal::KilnProcesses(_) => EXIT_BUSY,
        ReleaseRefusal::Store(_) => 1,
    }
}

/// The one line a release prints.
pub fn released_line(proved: &ReleaseProved) -> String {
    let r = &proved.released.reservation;
    format!(
        "released {} owner_uid={} sandboxes=1 host_cpu_millis={} memory_bytes={} pids={} disk_bytes={} inventory_sha256={}",
        proved.sandbox_id,
        proved.released.owner_uid,
        r.host_cpu_millis,
        r.memory_bytes,
        r.pids,
        r.disk_bytes,
        proved.inventory_sha256
    )
}

/// Whether opening the store failed only because another process holds its lock.
pub fn lock_held(error: &anyhow::Error) -> bool {
    error.downcast_ref::<crate::lock::AlreadyOwned>().is_some()
}

/// A sandbox ID as the API prints one: `sb-` and 16 lowercase hex digits.
pub fn valid_sandbox_id(id: &str) -> std::result::Result<(), String> {
    crate::expiry::key(id)
        .filter(|key| crate::expiry::id(*key) == id)
        .map(|_| ())
        .ok_or_else(|| format!("--sandbox {id:?} is not a sandbox ID (sb- and 16 hex digits)"))
}

/// The state directory's owner and that account's primary group, read without
/// following a link at the directory itself. Root never owns an instance's state.
pub fn state_owner(state_dir: &Path) -> Result<(u32, u32)> {
    use std::os::unix::fs::OpenOptionsExt;
    if !state_dir.is_absolute() || state_dir.components().any(|c| c == Component::ParentDir) {
        bail!("--state-dir must be absolute, without '..'");
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir)
        .with_context(|| format!("open {} without following links", state_dir.display()))?;
    let uid = directory.metadata()?.uid();
    if uid == 0 {
        bail!(
            "{} belongs to root, not to an instance's account",
            state_dir.display()
        );
    }
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pwd.pw_uid != uid {
        bail!(
            "{} belongs to uid {uid}, which has no account",
            state_dir.display()
        );
    }
    Ok((uid, pwd.pw_gid))
}

/// kiln's runs directory, opened by root and listed through that descriptor, so the
/// listing still works once root is given up. It must be root's alone.
#[derive(Debug)]
pub struct RunsRoot {
    fd: OwnedFd,
}

impl RunsRoot {
    pub fn open(path: &Path) -> Result<Self> {
        let name = CString::new(path.as_os_str().as_bytes()).context("path contains NUL")?;
        // SAFETY: name is NUL-terminated and the flags are valid for open.
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open kiln's runs directory {}", path.display()));
        }
        // SAFETY: open returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let meta = std::fs::File::from(fd.try_clone()?).metadata()?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!("{} is not root's alone", path.display());
        }
        Ok(Self { fd })
    }
}

impl RunsRoot {
    pub fn entries(&self) -> Result<Vec<OsString>> {
        // fdopendir owns the descriptor it is given: give it a duplicate, and read from
        // the start whatever an earlier listing did.
        let dup = self.fd.try_clone()?;
        // SAFETY: dup is an open directory descriptor whose ownership passes to the
        // stream; closedir below closes it.
        let dir = unsafe { libc::fdopendir(dup.as_raw_fd()) };
        if dir.is_null() {
            return Err(std::io::Error::last_os_error()).context("read kiln's runs directory");
        }
        std::mem::forget(dup);
        // SAFETY: dir is a live stream until closedir.
        unsafe { libc::rewinddir(dir) };
        let mut names = Vec::new();
        let result = loop {
            // readdir reports an error only through errno, so clear it first.
            set_errno(0);
            // SAFETY: dir is a live stream; the entry is valid until the next call.
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                break match error.raw_os_error() {
                    Some(0) | None => Ok(()),
                    _ => Err(error),
                };
            }
            // SAFETY: d_name is NUL-terminated within the entry.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name = name.to_bytes();
            if name != b"." && name != b".." {
                names.push(OsString::from_vec(name.to_vec()));
            }
        };
        // SAFETY: dir is live and closed exactly once.
        unsafe { libc::closedir(dir) };
        result.context("read kiln's runs directory")?;
        Ok(names)
    }
}

/// Takes the helper's serving lock as root, before anything else the proof needs: while
/// it is held no kilnd-helper serves, so nothing new can start a kiln create. Held means
/// a helper (or another release) is running: exit 75.
pub fn take_helper_fence(path: &Path) -> std::result::Result<ServeLock, (u8, String)> {
    ServeLock::acquire(path).map_err(|error| match error {
        ServeLockError::Held(path) => (
            EXIT_BUSY,
            format!(
                "{} is held: kilnd-helper is serving (or another release-ambiguous is running); stop kilnd-helper.socket and kilnd-helper and retry",
                path.display()
            ),
        ),
        ServeLockError::Other(error) => (1, format!("take the helper's serving lock: {error:#}")),
    })
}

/// Everything the command takes as root before it forks, in order: the fence first, then
/// kiln's runs directory.
pub fn root_prerequisites(
    helper_lock: &Path,
    runs: &Path,
) -> std::result::Result<(ServeLock, RunsRoot), (u8, String)> {
    let fence = take_helper_fence(helper_lock)?;
    let runs = RunsRoot::open(runs).map_err(|e| (EXIT_NOT_PROVED, format!("{e:#}")))?;
    Ok((fence, runs))
}

/// The client path of the private helper's abstract socket `name` (see
/// `helper::client::connect`).
pub fn abstract_helper_path(name: &str) -> PathBuf {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(name.as_bytes());
    PathBuf::from(OsString::from_vec(bytes))
}

/// The identity of the configured kiln executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KilnImage {
    pub dev: u64,
    pub ino: u64,
}

impl KilnImage {
    pub fn of(path: &Path) -> io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

/// One process's `stat`: its parent and its start time (fields 4 and 22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStat {
    pub ppid: i32,
    pub start: String,
}

impl ProcessStat {
    /// Parses `/proc/PID/stat`, whose command name is parenthesized and may hold spaces
    /// and parentheses: the fields after its last `") "` begin at field 3.
    pub fn parse(text: &str) -> io::Result<Self> {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed stat");
        let (_, fields) = text.rsplit_once(") ").ok_or_else(malformed)?;
        let fields: Vec<&str> = fields.split_whitespace().collect();
        let ppid = fields.get(1).and_then(|f| f.parse().ok()).ok_or_else(malformed)?;
        let start = fields.get(19).ok_or_else(malformed)?.to_string();
        Ok(Self { ppid, start })
    }
}

/// The four uids on a `/proc/PID/status` `Uid:` line: real, effective, saved and
/// filesystem, as root's user namespace sees them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessUids(pub [u32; 4]);

impl ProcessUids {
    /// Parses `/proc/PID/status`: its one `Uid:` line, with exactly four uids.
    pub fn parse(text: &str) -> io::Result<Self> {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed status Uid line");
        let mut lines = text.lines().filter_map(|line| line.strip_prefix("Uid:"));
        let (Some(line), None) = (lines.next(), lines.next()) else {
            return Err(malformed());
        };
        let uids: Vec<u32> = line
            .split_whitespace()
            .map(|uid| uid.parse().map_err(|_| malformed()))
            .collect::<io::Result<_>>()?;
        Ok(Self(uids.try_into().map_err(|_| malformed())?))
    }

    /// Whether the process holds root by any of its uids.
    pub fn any_root(self) -> bool {
        self.0.contains(&0)
    }
}

/// The node's processes as root reads them. Each per-process read answers `None` once
/// the process is gone (ENOENT or ESRCH, as when it exited mid-scan) or has no image (a
/// kernel thread, a zombie); every other error is an error.
pub trait ProcessTable {
    fn pids(&self) -> io::Result<Vec<i32>>;
    /// The text of `/proc/PID/exe`, ` (deleted)` included.
    fn exe_link(&self, pid: i32) -> io::Result<Option<Vec<u8>>>;
    /// The device and inode of the image `/proc/PID/exe` resolves to.
    fn exe_image(&self, pid: i32) -> io::Result<Option<KilnImage>>;
    /// The uids of `/proc/PID/status`.
    fn uids(&self, pid: i32) -> io::Result<Option<ProcessUids>>;
    fn stat(&self, pid: i32) -> io::Result<Option<ProcessStat>>;
    fn argv(&self, pid: i32) -> io::Result<Option<Vec<Vec<u8>>>>;
}

/// Published shims, by pid: each run directory's `shim.pid` and `shim.start` (kiln
/// `runtime/src/container.rs:139`, `publish_shim_identity`).
pub type PublishedShims = HashMap<i32, String>;

/// kiln's node services: subcommands that never create a run (kiln
/// `runtime/src/main.rs:116-136,421-425`, run by kiln-dns, kiln-network-setup,
/// kiln-metrics and kiln-metrics-collect). kiln's CLI has no global options, so its
/// first argument is the subcommand, and a shim keeps the argv of the `create` that
/// forked it.
const KILN_NODE_SERVICES: [&[u8]; 4] = [b"dns", b"network-setup", b"metrics", b"metrics-collect"];

/// The longest ancestry walked from one process before it counts as unexplained.
const MAX_ANCESTRY: usize = 4096;

/// A kiln process: its image is the configured kiln's, whoever runs it, or its
/// executable's name is `kiln` and it holds root by any uid. The name rule catches a kiln
/// that root started from a binary since replaced or deleted (every helper-started CLI
/// and setup shim runs as root). Another account's process can't create a run in kiln's
/// root-only runs directory, so a name it chose is no evidence: without the uid check
/// any local account could keep the release refused with `cp /bin/sleep ~/kiln; ~/kiln
/// 86400`.
fn is_kiln(table: &dyn ProcessTable, pid: i32, link: &[u8], kiln: KilnImage) -> io::Result<Option<bool>> {
    let path = link.strip_suffix(b" (deleted)").unwrap_or(link);
    let name = path.rsplit(|b| *b == b'/').next().unwrap_or(path);
    if name == b"kiln" {
        match table.uids(pid)? {
            None => return Ok(None),
            Some(uids) if uids.any_root() => return Ok(Some(true)),
            Some(_) => {}
        }
    }
    Ok(table.exe_image(pid)?.map(|image| image == kiln))
}

fn is_published(shims: &PublishedShims, pid: i32, stat: &ProcessStat) -> bool {
    shims.get(&pid).is_some_and(|start| *start == stat.start)
}

/// Whether an ancestor of the process whose parent is `ppid` is a published shim.
fn descends_from_shim(table: &dyn ProcessTable, mut ppid: i32, shims: &PublishedShims) -> io::Result<bool> {
    for _ in 0..MAX_ANCESTRY {
        if ppid <= 1 {
            return Ok(false);
        }
        let Some(stat) = table.stat(ppid)? else {
            // The ancestor exited: unexplained, and the operator retries.
            return Ok(false);
        };
        if is_published(shims, ppid, &stat) {
            return Ok(true);
        }
        ppid = stat.ppid;
    }
    Ok(false)
}

/// One pass: every kiln process that is not a published shim, a descendant of one, or a
/// kiln node service, as `PID EXE` (the first [`KilnProcesses::NAMED`] by name).
pub fn unexplained_in_one_pass(
    table: &dyn ProcessTable,
    kiln: KilnImage,
    shims: &PublishedShims,
) -> io::Result<KilnProcesses> {
    let mut found = KilnProcesses::default();
    for pid in table.pids()? {
        let Some(link) = table.exe_link(pid)? else {
            continue;
        };
        match is_kiln(table, pid, &link, kiln)? {
            Some(true) => {}
            Some(false) | None => continue,
        }
        let Some(stat) = table.stat(pid)? else {
            continue;
        };
        if is_published(shims, pid, &stat) || descends_from_shim(table, stat.ppid, shims)? {
            continue;
        }
        let Some(argv) = table.argv(pid)? else {
            continue;
        };
        if argv
            .get(1)
            .is_some_and(|command| KILN_NODE_SERVICES.contains(&command.as_slice()))
        {
            continue;
        }
        found.push(format!("{pid} {}", String::from_utf8_lossy(&link)));
    }
    Ok(found)
}

/// Step 5 of the proof, as root. Two complete passes, each with the run directories'
/// published shims read afresh: no helper serves and nothing else starts a create, so
/// after a first pass that found no kiln CLI every setup shim that still exists was
/// forked before that pass ended, and the second pass lists it.
pub fn unexplained_kiln_processes(
    table: &dyn ProcessTable,
    kiln: KilnImage,
    shims: &dyn Fn() -> io::Result<PublishedShims>,
) -> io::Result<KilnProcesses> {
    for _ in 0..2 {
        let found = unexplained_in_one_pass(table, kiln, &shims()?)?;
        if !found.is_empty() {
            return Ok(found);
        }
    }
    Ok(KilnProcesses::default())
}

/// A short file below a directory descriptor, opened without following a link; `None`
/// if it doesn't exist.
fn read_small_at(dir: &impl AsRawFd, name: &str) -> io::Result<Option<String>> {
    let c_name = CString::new(name)?;
    // SAFETY: a live directory descriptor, a NUL-terminated name and valid flags.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            _ => Err(error),
        };
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut text = String::new();
    file.take(65).read_to_string(&mut text)?;
    if text.len() > 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} is too long")));
    }
    Ok(Some(text.trim().to_string()))
}

impl RunsRoot {
    /// Every run directory's published shim. A run without both files, or with a pid
    /// that doesn't parse, publishes none: a process claiming it is unexplained, and the
    /// runs directory read still names the run itself.
    pub fn published_shims(&self) -> io::Result<PublishedShims> {
        let mut shims = PublishedShims::new();
        for name in self.entries().map_err(io::Error::other)? {
            if name == crate::manager::KILN_RUNS_RESERVED {
                continue;
            }
            let c_name = CString::new(name.as_bytes())?;
            // SAFETY: a live directory descriptor, a NUL-terminated name and valid flags.
            let fd = unsafe {
                libc::openat(
                    self.fd.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    // Removed since the listing, or not a directory: no shim.
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => continue,
                    _ => return Err(error),
                }
            }
            // SAFETY: openat returned a new owned descriptor.
            let run = unsafe { OwnedFd::from_raw_fd(fd) };
            let (Some(pid), Some(start)) = (read_small_at(&run, "shim.pid")?, read_small_at(&run, "shim.start")?) else {
                continue;
            };
            if let Ok(pid) = pid.parse::<i32>()
                && pid > 0
            {
                shims.insert(pid, start);
            }
        }
        Ok(shims)
    }
}

/// The scan request byte on the parent's control socket. Each request is answered with a
/// four-byte big-endian length and that much JSON: `{"processes": [...], "total": N}`,
/// at most [`KilnProcesses::NAMED`] processes named and `N` counting them all, or
/// `{"error": "..."}`. Parent and child are the one binary, forked, so the shape has no
/// versions.
const SCAN: u8 = b'S';
/// The largest scan reply. The named processes bound a reply well below it: 64 exe links,
/// each at most `PATH_MAX` plus ` (deleted)`.
const MAX_SCAN_REPLY: usize = 1 << 20;

/// The child's view of the node: kiln's runs directory through root's descriptor, and
/// the process scan through the root half's control socket.
pub struct ChildNode {
    pub runs: RunsRoot,
    pub control: UnixStream,
}

impl ReleaseNode for ChildNode {
    fn entries(&self) -> Result<Vec<OsString>> {
        self.runs.entries()
    }

    fn kiln_processes(&self) -> Result<KilnProcesses> {
        let mut control = &self.control;
        control.write_all(&[SCAN]).context("ask root for the process scan")?;
        let mut length = [0u8; 4];
        control.read_exact(&mut length).context("read the process scan")?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_SCAN_REPLY {
            bail!("malformed process scan reply");
        }
        let mut reply = vec![0u8; length];
        control.read_exact(&mut reply).context("read the process scan")?;
        let reply: serde_json::Value = serde_json::from_slice(&reply)?;
        if let Some(error) = reply.get("error").and_then(|e| e.as_str()) {
            bail!("{error}");
        }
        let named: Vec<String> = reply
            .get("processes")
            .and_then(|p| p.as_array())
            .and_then(|p| p.iter().map(|v| v.as_str().map(str::to_string)).collect())
            .context("malformed process scan reply")?;
        let total = reply
            .get("total")
            .and_then(|t| t.as_u64())
            .and_then(|t| usize::try_from(t).ok())
            .context("malformed process scan reply")?;
        // As KilnProcesses::push builds it: every process named up to the cap.
        if named.len() != total.min(KilnProcesses::NAMED) {
            bail!("malformed process scan reply");
        }
        Ok(KilnProcesses { named, total })
    }
}

/// The root half: until the child closes its control socket, serve the helper
/// protocol's kiln group (and its checkpoint group, if asked) on `listener` to `uid`
/// alone, and answer each scan with `scan`'s result. Every request settles before this
/// returns.
pub async fn serve_root_half(
    listener: tokio::net::UnixListener,
    control: UnixStream,
    uid: u32,
    kiln: PathBuf,
    checkpoints: bool,
    scan: impl Fn() -> io::Result<KilnProcesses> + Send + Sync + 'static,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let checkpoint = if checkpoints {
        let workers = std::sync::Arc::new(crate::helper::checkpoint::KilnWorkers::new(kiln.clone()));
        Some(crate::helper::checkpoint::Node::new(workers).context("start the checkpoint group")?)
    } else {
        None
    };
    let stop = tokio_util::sync::CancellationToken::new();
    let served = tokio::spawn(crate::helper::serve_with_groups(
        listener,
        uid,
        kiln,
        None,
        checkpoint.clone(),
        stop.clone(),
    ));
    control.set_nonblocking(true)?;
    let mut control = tokio::net::UnixStream::from_std(control)?;
    let scan = std::sync::Arc::new(scan);
    let mut request = [0u8; 1];
    let answered: Result<()> = async {
        loop {
            match control.read(&mut request).await {
                Ok(0) => return Ok(()),
                Ok(_) if request[0] == SCAN => {}
                Ok(_) => bail!("unknown control request"),
                Err(error) => return Err(error.into()),
            }
            let scan = scan.clone();
            let reply = match tokio::task::spawn_blocking(move || scan()).await? {
                Ok(found) => serde_json::json!({ "processes": found.named, "total": found.total }),
                Err(error) => serde_json::json!({ "error": format!("{error}") }),
            };
            let reply = serde_json::to_vec(&reply)?;
            if reply.len() > MAX_SCAN_REPLY {
                bail!("process scan reply is too large");
            }
            control.write_all(&(reply.len() as u32).to_be_bytes()).await?;
            control.write_all(&reply).await?;
        }
    }
    .await;
    stop.cancel();
    let served = served.await.context("join the private helper")?;
    if let Some(node) = checkpoint {
        node.shutdown().await;
    }
    answered?;
    served.context("private helper")
}

/// Root's process table, read beneath kilnd's private procfs instance.
#[cfg(target_os = "linux")]
pub struct LinuxProcesses;

#[cfg(target_os = "linux")]
fn gone<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
impl ProcessTable for LinuxProcesses {
    fn pids(&self) -> io::Result<Vec<i32>> {
        // pid_max is at most 2^22.
        let entries = crate::sys::procfs::read_root_dir(1 << 23)?;
        Ok(entries
            .iter()
            .filter_map(|entry| std::str::from_utf8(&entry.name).ok()?.parse().ok())
            .filter(|pid: &i32| *pid > 0)
            .collect())
    }

    fn exe_link(&self, pid: i32) -> io::Result<Option<Vec<u8>>> {
        let Some(dir) = gone(crate::sys::procfs::open_dir(&pid.to_string()))? else {
            return Ok(None);
        };
        gone(crate::sys::read_link_at(&dir, c"exe"))
    }

    fn exe_image(&self, pid: i32) -> io::Result<Option<KilnImage>> {
        let Some(image) = gone(crate::sys::procfs::open_image(pid))? else {
            return Ok(None);
        };
        let meta = image.metadata()?;
        Ok(Some(KilnImage {
            dev: meta.dev(),
            ino: meta.ino(),
        }))
    }

    fn uids(&self, pid: i32) -> io::Result<Option<ProcessUids>> {
        gone(crate::sys::procfs::read_to_string(&format!("{pid}/status")))?
            .map(|text| ProcessUids::parse(&text))
            .transpose()
    }

    fn stat(&self, pid: i32) -> io::Result<Option<ProcessStat>> {
        gone(crate::sys::procfs::read_to_string(&format!("{pid}/stat")))?
            .map(|text| ProcessStat::parse(&text))
            .transpose()
    }

    fn argv(&self, pid: i32) -> io::Result<Option<Vec<Vec<u8>>>> {
        let Some(file) = gone(crate::sys::procfs::open(&format!("{pid}/cmdline"), libc::O_RDONLY))? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(1 << 16).read_to_end(&mut bytes)?;
        // Each argument ends in a NUL; a kernel thread or zombie has none.
        let bytes = bytes.strip_suffix(b"\0").unwrap_or(&bytes);
        if bytes.is_empty() {
            return Ok(Some(Vec::new()));
        }
        Ok(Some(bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect()))
    }
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    // SAFETY: __errno_location returns this thread's errno.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    // SAFETY: __error returns this thread's errno.
    unsafe { *libc::__error() = value };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const KILN: KilnImage = KilnImage { dev: 1, ino: 100 };
    const OTHER: KilnImage = KilnImage { dev: 1, ino: 200 };
    const ROOT: [u32; 4] = [0; 4];
    const MALLORY: [u32; 4] = [1000; 4];

    #[derive(Clone)]
    struct Proc {
        link: &'static str,
        image: KilnImage,
        uids: [u32; 4],
        ppid: i32,
        start: &'static str,
        argv: &'static [&'static str],
    }

    fn kiln_proc(ppid: i32, start: &'static str, argv: &'static [&'static str]) -> Proc {
        Proc {
            link: "/usr/local/bin/kiln",
            image: KILN,
            uids: ROOT,
            ppid,
            start,
            argv,
        }
    }

    /// A process table; `hidden_first` pids are missing from the first listing, as a
    /// process forked while that listing ran can be. `failing` pids' exe link fails.
    #[derive(Default)]
    struct Table {
        procs: HashMap<i32, Proc>,
        hidden_first: Vec<i32>,
        failing: Vec<(i32, i32)>,
        listings: Cell<u32>,
    }

    impl ProcessTable for Table {
        fn pids(&self) -> io::Result<Vec<i32>> {
            let first = self.listings.get() == 0;
            self.listings.set(self.listings.get() + 1);
            let mut pids: Vec<i32> = self
                .procs
                .keys()
                .chain(self.failing.iter().map(|(pid, _)| pid))
                .copied()
                .filter(|pid| !(first && self.hidden_first.contains(pid)))
                .collect();
            pids.sort();
            Ok(pids)
        }
        fn exe_link(&self, pid: i32) -> io::Result<Option<Vec<u8>>> {
            if let Some((_, errno)) = self.failing.iter().find(|(p, _)| *p == pid) {
                return Err(io::Error::from_raw_os_error(*errno));
            }
            Ok(self.procs.get(&pid).map(|p| p.link.as_bytes().to_vec()))
        }
        fn exe_image(&self, pid: i32) -> io::Result<Option<KilnImage>> {
            Ok(self.procs.get(&pid).map(|p| p.image))
        }
        fn uids(&self, pid: i32) -> io::Result<Option<ProcessUids>> {
            Ok(self.procs.get(&pid).map(|p| ProcessUids(p.uids)))
        }
        fn stat(&self, pid: i32) -> io::Result<Option<ProcessStat>> {
            Ok(self.procs.get(&pid).map(|p| ProcessStat {
                ppid: p.ppid,
                start: p.start.to_string(),
            }))
        }
        fn argv(&self, pid: i32) -> io::Result<Option<Vec<Vec<u8>>>> {
            Ok(self
                .procs
                .get(&pid)
                .map(|p| p.argv.iter().map(|a| a.as_bytes().to_vec()).collect()))
        }
    }

    fn scan(table: &Table, shims: &[(i32, &str)]) -> io::Result<Vec<String>> {
        let shims: PublishedShims = shims.iter().map(|(p, s)| (*p, s.to_string())).collect();
        let found = unexplained_kiln_processes(table, KILN, &|| Ok(shims.clone()))?;
        assert_eq!(found.total, found.named.len());
        Ok(found.named)
    }

    const CREATE: &[&str] = &["/usr/local/bin/kiln", "create", "--image=alpine"];

    #[test]
    fn a_setup_shim_or_a_surviving_cli_is_unexplained() {
        let mut table = Table::default();
        // A shim forked by a create whose CLI the stopped helper killed: reparented, with
        // no run directory (or none published) yet.
        table.procs.insert(10, kiln_proc(1, "500", CREATE));
        // A kiln exec CLI the helper started.
        table
            .procs
            .insert(11, kiln_proc(1, "501", &["/usr/local/bin/kiln", "exec", "ab", "sleep"]));
        assert_eq!(
            scan(&table, &[]).unwrap(),
            ["10 /usr/local/bin/kiln", "11 /usr/local/bin/kiln"]
        );
    }

    #[test]
    fn a_published_shim_and_its_descendants_are_explained() {
        let mut table = Table::default();
        table.procs.insert(20, kiln_proc(1, "600", CREATE));
        // The sandbox init, a clone of the shim with kiln's image.
        table.procs.insert(21, kiln_proc(20, "601", CREATE));
        // A workload, and a binary in the image that happens to be called kiln.
        table.procs.insert(
            22,
            Proc {
                link: "/bin/busybox",
                image: OTHER,
                uids: ROOT,
                ppid: 21,
                start: "602",
                argv: &["sh"],
            },
        );
        table.procs.insert(
            23,
            Proc {
                link: "/usr/bin/kiln",
                image: OTHER,
                uids: ROOT,
                ppid: 22,
                start: "603",
                argv: &["kiln"],
            },
        );
        assert_eq!(scan(&table, &[(20, "600")]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_shim_whose_start_time_differs_from_shim_start_is_unexplained() {
        let mut table = Table::default();
        table.procs.insert(30, kiln_proc(1, "700", CREATE));
        // Its init counts as a descendant of nothing published either.
        table.procs.insert(31, kiln_proc(30, "701", CREATE));
        assert_eq!(
            scan(&table, &[(30, "699")]).unwrap(),
            ["30 /usr/local/bin/kiln", "31 /usr/local/bin/kiln"]
        );
    }

    #[test]
    fn a_replaced_deleted_or_renamed_kiln_is_still_kiln() {
        let mut table = Table::default();
        // Started from a kiln binary since replaced: another inode, the old name.
        table.procs.insert(
            40,
            Proc {
                link: "/usr/local/bin/kiln (deleted)",
                image: OTHER,
                uids: ROOT,
                ppid: 1,
                start: "800",
                argv: CREATE,
            },
        );
        table.procs.insert(
            41,
            Proc {
                link: "/var/tmp/stand-in/kiln (deleted)",
                image: OTHER,
                uids: ROOT,
                ppid: 1,
                start: "801",
                argv: &["kiln", "300"],
            },
        );
        // The configured image under another name.
        table.procs.insert(
            42,
            Proc {
                link: "/opt/k2",
                image: KILN,
                uids: ROOT,
                ppid: 1,
                start: "802",
                argv: CREATE,
            },
        );
        // Not kiln at all.
        table.procs.insert(
            43,
            Proc {
                link: "/usr/bin/kilnd",
                image: OTHER,
                uids: ROOT,
                ppid: 1,
                start: "803",
                argv: &["kilnd"],
            },
        );
        assert_eq!(
            scan(&table, &[]).unwrap(),
            [
                "40 /usr/local/bin/kiln (deleted)",
                "41 /var/tmp/stand-in/kiln (deleted)",
                "42 /opt/k2"
            ]
        );
    }

    #[test]
    fn kilns_node_services_are_explained_and_nothing_else_is() {
        let mut table = Table::default();
        table
            .procs
            .insert(50, kiln_proc(1, "900", &["/usr/local/bin/kiln", "dns"]));
        table.procs.insert(
            51,
            kiln_proc(
                1,
                "901",
                &["/usr/local/bin/kiln", "metrics", "--snapshot", "--listen", "127.0.0.1:9840"],
            ),
        );
        table
            .procs
            .insert(52, kiln_proc(1, "902", &["/usr/local/bin/kiln", "metrics-collect"]));
        table
            .procs
            .insert(53, kiln_proc(1, "903", &["/usr/local/bin/kiln", "network-setup"]));
        table
            .procs
            .insert(54, kiln_proc(1, "904", &["/usr/local/bin/kiln", "ls"]));
        table.procs.insert(55, kiln_proc(1, "905", &[]));
        assert_eq!(
            scan(&table, &[]).unwrap(),
            ["54 /usr/local/bin/kiln", "55 /usr/local/bin/kiln"]
        );
    }

    #[test]
    fn a_process_gone_mid_scan_is_skipped_and_any_other_error_refuses() {
        let mut table = Table::default();
        // Listed, then gone before its exe was read: the table answers None.
        table.failing.push((60, libc::EACCES));
        assert_eq!(
            scan(&table, &[]).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        struct Gone;
        impl ProcessTable for Gone {
            fn pids(&self) -> io::Result<Vec<i32>> {
                Ok(vec![70])
            }
            fn exe_link(&self, _: i32) -> io::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn exe_image(&self, _: i32) -> io::Result<Option<KilnImage>> {
                unreachable!()
            }
            fn uids(&self, _: i32) -> io::Result<Option<ProcessUids>> {
                unreachable!()
            }
            fn stat(&self, _: i32) -> io::Result<Option<ProcessStat>> {
                unreachable!()
            }
            fn argv(&self, _: i32) -> io::Result<Option<Vec<Vec<u8>>>> {
                unreachable!()
            }
        }
        assert!(
            unexplained_kiln_processes(&Gone, KILN, &|| Ok(PublishedShims::new()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_shim_the_first_pass_missed_is_in_the_second() {
        let mut table = Table::default();
        table.procs.insert(80, kiln_proc(1, "950", CREATE));
        table.hidden_first.push(80);
        assert_eq!(scan(&table, &[]).unwrap(), ["80 /usr/local/bin/kiln"]);
        assert_eq!(table.listings.get(), 2);
    }

    /// Review 2026-11-22 (spare kilnd security, LOW 1): a binary named kiln that another
    /// account runs from its own home, a login shell's child, is no kiln process: it can't
    /// create a run in kiln's root-only runs directory, and before the uid check any local
    /// account kept the release refused with `cp /bin/sleep ~/kiln; ~/kiln 86400`. The
    /// same name under root still refuses, and the configured image counts whoever runs it.
    #[test]
    fn another_accounts_binary_named_kiln_is_ignored_and_roots_still_refuses() {
        let mut table = Table::default();
        table.procs.insert(
            4242,
            Proc {
                link: "/home/mallory/kiln",
                image: OTHER,
                uids: MALLORY,
                ppid: 3000,
                start: "123456",
                argv: &["/home/mallory/kiln", "86400"],
            },
        );
        table.procs.insert(
            3000,
            Proc {
                link: "/bin/bash",
                image: OTHER,
                uids: MALLORY,
                ppid: 1,
                start: "123000",
                argv: &["-bash"],
            },
        );
        // Deleted under it, as a replaced kiln's would be: still not root's.
        table.procs.insert(
            4243,
            Proc {
                link: "/home/mallory/kiln (deleted)",
                image: OTHER,
                uids: MALLORY,
                ppid: 3000,
                start: "123457",
                argv: &["/home/mallory/kiln", "86400"],
            },
        );
        assert_eq!(scan(&table, &[]).unwrap(), Vec::<String>::new());

        // The same process holding root by any one of its uids is kiln.
        for (i, uids) in [ROOT, [1000, 0, 1000, 1000], [1000, 1000, 0, 1000], [1000, 1000, 1000, 0]]
            .into_iter()
            .enumerate()
        {
            table.procs.get_mut(&4242).unwrap().uids = uids;
            assert_eq!(scan(&table, &[]).unwrap(), ["4242 /home/mallory/kiln"], "{i}");
            let refusal = ReleaseRefusal::KilnProcesses(["4242 /home/mallory/kiln"].into_iter().collect());
            assert_eq!(refusal_exit(&refusal), EXIT_BUSY);
        }
        table.procs.get_mut(&4242).unwrap().uids = MALLORY;

        // The configured image counts whoever runs it, under any name.
        table.procs.insert(
            4244,
            Proc {
                link: "/usr/local/bin/kiln",
                image: KILN,
                uids: MALLORY,
                ppid: 3000,
                start: "123458",
                argv: &["/usr/local/bin/kiln", "ls"],
            },
        );
        table.procs.insert(
            4245,
            Proc {
                link: "/home/mallory/k",
                image: KILN,
                uids: MALLORY,
                ppid: 3000,
                start: "123459",
                argv: &["k", "ls"],
            },
        );
        assert_eq!(
            scan(&table, &[]).unwrap(),
            ["4244 /usr/local/bin/kiln", "4245 /home/mallory/k"]
        );
    }

    /// A process gone between its exe link and its status is skipped, like any other
    /// read that finds it gone; a status read that fails otherwise refuses.
    #[test]
    fn a_kiln_named_process_whose_status_is_gone_is_skipped_and_an_error_refuses() {
        struct Racing(Option<i32>);
        impl ProcessTable for Racing {
            fn pids(&self) -> io::Result<Vec<i32>> {
                Ok(vec![90])
            }
            fn exe_link(&self, _: i32) -> io::Result<Option<Vec<u8>>> {
                Ok(Some(b"/usr/local/bin/kiln".to_vec()))
            }
            fn exe_image(&self, _: i32) -> io::Result<Option<KilnImage>> {
                unreachable!("read after the status")
            }
            fn uids(&self, _: i32) -> io::Result<Option<ProcessUids>> {
                match self.0 {
                    None => Ok(None),
                    Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                }
            }
            fn stat(&self, _: i32) -> io::Result<Option<ProcessStat>> {
                unreachable!()
            }
            fn argv(&self, _: i32) -> io::Result<Option<Vec<Vec<u8>>>> {
                unreachable!()
            }
        }
        let none = || Ok(PublishedShims::new());
        assert!(unexplained_kiln_processes(&Racing(None), KILN, &none).unwrap().is_empty());
        assert_eq!(
            unexplained_kiln_processes(&Racing(Some(libc::EACCES)), KILN, &none)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn status_uids_are_the_one_uid_line_with_four_uids() {
        let status = "Name:\tkiln\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t4242\nPPid:\t1\nUid:\t1000\t0\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        let uids = ProcessUids::parse(status).unwrap();
        assert_eq!(uids, ProcessUids([1000, 0, 1000, 1000]));
        assert!(uids.any_root());
        assert!(!ProcessUids::parse("Uid:\t1000\t1000\t1000\t1000\n").unwrap().any_root());
        for bad in [
            "Name:\tkiln\n",
            "Uid:\t1000\t1000\t1000\n",
            "Uid:\t1000\t1000\t1000\t1000\t1000\n",
            "Uid:\t1000\t-1\t1000\t1000\n",
            "Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n",
        ] {
            assert!(ProcessUids::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// However many processes match, the scan names the first 64 and counts them all,
    /// and the refusal says how many it left out.
    #[test]
    fn many_unexplained_processes_are_named_up_to_the_cap_and_counted() {
        let mut table = Table::default();
        for pid in 1000..1200 {
            table.procs.insert(pid, kiln_proc(1, "1", CREATE));
        }
        let found = unexplained_kiln_processes(&table, KILN, &|| Ok(PublishedShims::new())).unwrap();
        assert_eq!(found.total, 200);
        assert_eq!(found.named.len(), KilnProcesses::NAMED);
        assert_eq!(found.named[0], "1000 /usr/local/bin/kiln");
        assert_eq!(found.named[63], "1063 /usr/local/bin/kiln");
        let refusal = ReleaseRefusal::KilnProcesses(found).to_string();
        assert!(
            refusal.contains("1063 /usr/local/bin/kiln and 136 more (200 in all); "),
            "{refusal}"
        );
        assert!(!refusal.contains("1064 "), "{refusal}");
        let few: KilnProcesses = ["7 /usr/local/bin/kiln"].into_iter().collect();
        let refusal = ReleaseRefusal::KilnProcesses(few).to_string();
        assert!(refusal.contains("descendants: 7 /usr/local/bin/kiln; "), "{refusal}");
        assert!(!refusal.contains("in all"), "{refusal}");
    }

    #[test]
    fn stat_parses_past_a_command_name_with_spaces_and_parentheses() {
        let text = "4242 (ki ln) (x) S 77 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 31337 1 2 3";
        assert_eq!(
            ProcessStat::parse(text).unwrap(),
            ProcessStat {
                ppid: 77,
                start: "31337".into()
            }
        );
        assert!(ProcessStat::parse("4242 (kiln) S 77").is_err());
    }

    fn runs_root(path: &Path) -> RunsRoot {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(fd >= 0);
        RunsRoot {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::File::options()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    #[test]
    fn published_shims_are_the_runs_with_both_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        for run in ["published", "pid-only", ".checkpoints", "bad-pid"] {
            std::fs::create_dir(dir.path().join(run)).unwrap();
        }
        write(&dir.path().join("published/shim.pid"), "4242
");
        write(&dir.path().join("published/shim.start"), "555
");
        write(&dir.path().join("pid-only/shim.pid"), "4243
");
        write(&dir.path().join(".checkpoints/shim.pid"), "4244
");
        write(&dir.path().join(".checkpoints/shim.start"), "1
");
        write(&dir.path().join("bad-pid/shim.pid"), "-1
");
        write(&dir.path().join("bad-pid/shim.start"), "1
");
        write(&dir.path().join("a-file"), "");
        std::os::unix::fs::symlink(dir.path().join("published"), dir.path().join("link"))
            .unwrap();
        let shims = runs_root(dir.path()).published_shims().unwrap();
        assert_eq!(shims, PublishedShims::from([(4242, "555".to_string())]));
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        dir
    }

    /// The fence comes first: with a helper serving, the command refuses 75 before it
    /// opens anything else, here a runs directory it would refuse for another reason.
    #[test]
    fn a_serving_helper_refuses_the_release_before_anything_else() {
        let dir = private_dir();
        let lock = dir.path().join("helper.lock");
        let serving = ServeLock::acquire(&lock).unwrap();
        let shared_runs = dir.path().join("runs");
        std::fs::create_dir(&shared_runs).unwrap();
        std::fs::set_permissions(&shared_runs, std::os::unix::fs::PermissionsExt::from_mode(0o777))
            .unwrap();
        let (code, message) = root_prerequisites(&lock, &shared_runs).unwrap_err();
        assert_eq!(code, EXIT_BUSY, "{message}");
        assert!(message.contains("stop kilnd-helper"), "{message}");
        assert!(message.contains(&lock.display().to_string()), "{message}");
        drop(serving);
        // Free again, it gets as far as the runs directory.
        let (code, message) = root_prerequisites(&lock, &shared_runs).unwrap_err();
        assert_eq!(code, EXIT_NOT_PROVED, "{message}");
    }

    /// A helper that starts while the release holds the fence is refused, not queued.
    #[test]
    fn a_helper_starting_while_the_release_holds_the_fence_does_not_serve() {
        let dir = private_dir();
        let lock = dir.path().join("helper.lock");
        let fence = take_helper_fence(&lock).unwrap();
        assert!(matches!(
            ServeLock::acquire(&lock),
            Err(ServeLockError::Held(_))
        ));
        drop(fence);
        ServeLock::acquire(&lock).unwrap();
    }

    #[tokio::test]
    async fn the_root_half_answers_scans_until_the_child_closes_its_socket() {
        let dir = private_dir();
        let listener = tokio::net::UnixListener::bind(dir.path().join("h.sock")).unwrap();
        let (child, root) = UnixStream::pair().unwrap();
        // Last first. Before the cap, about 256 processes under paths near PATH_MAX took
        // the reply past MAX_SCAN_REPLY, and the release refused naming none of them.
        let long = format!("/home/mallory/{}/kiln (deleted)", "d".repeat(4000));
        let many: KilnProcesses = (0..300).map(|pid| format!("{pid} {long}")).collect();
        let answers = std::sync::Mutex::new(vec![
            Ok(many.clone()),
            Err(io::Error::other("read 9/exe: Permission denied")),
            Ok(["7 /usr/local/bin/kiln"].into_iter().collect()),
        ]);
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let root = tokio::spawn(serve_root_half(
            listener,
            root,
            uid,
            PathBuf::from("/usr/local/bin/kiln"),
            false,
            move || answers.lock().unwrap().pop().unwrap(),
        ));
        let runs = dir.path().to_path_buf();
        let asked = tokio::task::spawn_blocking(move || {
            let node = ChildNode {
                runs: runs_root(&runs),
                control: child,
            };
            let first = node.kiln_processes().map_err(|e| e.to_string());
            let second = node.kiln_processes().map_err(|e| e.to_string());
            let third = node.kiln_processes().map_err(|e| e.to_string());
            (first, second, third)
        })
        .await
        .unwrap();
        assert_eq!(
            asked.0,
            Ok(KilnProcesses {
                named: vec!["7 /usr/local/bin/kiln".to_string()],
                total: 1
            })
        );
        assert!(asked.1.unwrap_err().contains("Permission denied"));
        let third = asked.2.unwrap();
        assert_eq!(third, many);
        assert_eq!((third.named.len(), third.total), (KilnProcesses::NAMED, 300));
        // The child's socket closed with it: the root half stops serving and returns.
        tokio::time::timeout(std::time::Duration::from_secs(10), root)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// The child accepts only the shape the root half writes: the processes named up to
    /// the cap, and a total that counts them.
    #[test]
    fn the_child_refuses_a_scan_reply_whose_total_does_not_match_its_names() {
        let dir = private_dir();
        for (reply, ok) in [
            (serde_json::json!({ "processes": ["7 /k"], "total": 1 }), true),
            (serde_json::json!({ "processes": [], "total": 0 }), true),
            (serde_json::json!({ "processes": ["7 /k"] }), false),
            (serde_json::json!({ "processes": ["7 /k"], "total": 2 }), false),
            (serde_json::json!({ "processes": [], "total": 1 }), false),
            (serde_json::json!({ "processes": ["7 /k"], "total": -1 }), false),
            (serde_json::json!({ "processes": ["7 /k"], "total": 0 }), false),
        ] {
            let (child, mut root) = UnixStream::pair().unwrap();
            let bytes = serde_json::to_vec(&reply).unwrap();
            root.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
            root.write_all(&bytes).unwrap();
            let node = ChildNode {
                runs: runs_root(dir.path()),
                control: child,
            };
            let got = node.kiln_processes();
            assert_eq!(got.is_ok(), ok, "{reply} {got:?}");
            let mut asked = [0u8; 1];
            root.read_exact(&mut asked).unwrap();
            assert_eq!(asked[0], SCAN);
        }
    }

    #[test]
    fn the_runs_listing_reads_every_entry_through_its_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["sb-run", ".checkpoints", ".removing-x"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }
        std::fs::File::options()
            .create_new(true)
            .write(true)
            .open(dir.path().join("stray"))
            .unwrap();
        // A tempdir is the test account's, not root's.
        let refused = RunsRoot::open(dir.path()).err().map(|e| e.to_string());
        if unsafe { libc::geteuid() } != 0 {
            assert!(refused.unwrap().contains("is not root's alone"));
        }
        let name = CString::new(dir.path().as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(fd >= 0);
        let runs = RunsRoot {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        for _ in 0..2 {
            let mut names = runs.entries().unwrap();
            names.sort();
            assert_eq!(names, [".checkpoints", ".removing-x", "sb-run", "stray"]);
        }
    }

    #[test]
    fn a_runs_directory_through_a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        assert!(RunsRoot::open(&dir.path().join("link")).is_err());
    }

    #[test]
    fn only_api_sandbox_ids_are_accepted() {
        assert!(valid_sandbox_id("sb-00000000000000ff").is_ok());
        for bad in [
            "",
            "sb-ff",
            "sb-00000000000000FF",
            "sb-00000000000000ff ",
            "../x",
            "fc-00000000000000ff",
        ] {
            assert!(valid_sandbox_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_state_directory_through_a_link_or_relative_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("state")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("state"), dir.path().join("link")).unwrap();
        assert!(state_owner(&dir.path().join("link")).is_err());
        assert!(state_owner(Path::new("relative/state")).is_err());
        assert!(state_owner(&dir.path().join("state/../state")).is_err());
        if unsafe { libc::geteuid() } != 0 {
            let (uid, _) = state_owner(&dir.path().join("state")).unwrap();
            assert_eq!(uid, unsafe { libc::geteuid() });
        }
    }
}
