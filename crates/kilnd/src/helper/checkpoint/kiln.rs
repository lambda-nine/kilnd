//! The checkpoint group's kiln CLI adapter: the fixed worker commands, their strict
//! output parsers and the host process table. Every worker is the configured kiln
//! executable with typed arguments (`KilnArgs`), run by kilnd's one subprocess runner:
//! cleared environment, parent-death SIGKILL, and a future that returns only after the
//! child was reaped.
use crate::checkpoint::CheckpointId;
use crate::checkpoint::wire::StorageFree;
use crate::helper::protocol::ItemKind;
use crate::model::{Digest, Id128};
use crate::process::{self, CaptureCompletion, Finish, KilnArgs, KilnBinary, Outcome};
use std::future::Future;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// kiln's operation 6 lease (kiln `docs/checkpoint-lease-v1.md`).
pub const FEATURE_CHECKPOINT_LEASE: u32 = 0x40;
/// Every worker's retained stdout and stderr. A listing of the 4,096-entry inventory
/// bound is about half of it; anything longer is incomplete, never trusted.
pub const WORKER_OUTPUT: usize = 1 << 20;

pub type WorkerFuture = Pin<Box<dyn Future<Output = io::Result<Outcome>> + Send>>;
pub type SupportFuture = Pin<Box<dyn Future<Output = Support> + Send>>;

/// What the installed kiln and host support (design 6.3 and 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Support {
    /// kiln lists format 1 and checks generations on removal: enough for removal and
    /// inventory.
    pub removal: bool,
    /// New captures and restores: removal's checks, kiln's leases, XFS with project
    /// quotas at runs and a trustworthy registry; or the first that failed.
    pub new_work: Result<(), String>,
}

/// One live process's arguments, for the untracked-worker scan: only a process running
/// the trusted kiln executable whose arguments read an artifact (see [`process_table`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessArgs {
    /// Part of a restored kiln sandbox, never a worker: the shim `setsid` made a
    /// session leader, or a process of that shim's session (the sandbox's init, which
    /// the shim forks without exec and so keeps its arguments). See [`shim_sessions`].
    pub in_shim_session: bool,
    pub argv: Vec<String>,
}

/// Marks the processes of restored sandboxes, from `(pid, session, argv)`: a session
/// leader whose arguments name a `--from-checkpoint` create is a sandbox shim, and a
/// process in its session naming the same artifact is one of its forks (kiln's
/// container init keeps the shim's arguments). Neither reads the artifact once the
/// restore is done, and during the restore the shim holds the artifact's lock, which
/// keeps kiln's own removal busy. A `kiln create` CLI the helper started is in the
/// helper's session, never a shim's, so it still counts.
pub fn shim_sessions(processes: Vec<(u32, u32, Vec<String>)>) -> Vec<ProcessArgs> {
    let shims: std::collections::HashMap<u32, String> = processes
        .iter()
        .filter(|(pid, session, _)| pid == session)
        .filter_map(|(pid, _, argv)| Some((*pid, source_text(argv)?)))
        .collect();
    processes
        .into_iter()
        .map(|(_, session, argv)| ProcessArgs {
            in_shim_session: source_text(&argv)
                .is_some_and(|source| shims.get(&session).is_some_and(|s| *s == source)),
            argv,
        })
        .collect()
}

/// How the checkpoint node starts workers and reads the process table. Tests replace
/// it; production is [`KilnWorkers`].
pub trait Workers: Send + Sync + 'static {
    /// Runs one kiln CLI. At the deadline or on cancellation it is killed, and the
    /// future resolves only once it was reaped. An unkillable child never resolves, so
    /// its caller keeps its slot and its artifact's dependency.
    fn run(&self, args: KilnArgs, deadline: Instant, cancel: CancellationToken) -> WorkerFuture;
    /// Every live process's arguments. An error means no absence can be certified.
    fn processes(&self) -> io::Result<Vec<ProcessArgs>>;
    /// What the installed CLI and the host support ([`Support`]).
    fn support(&self, deadline: Instant, cancel: CancellationToken) -> SupportFuture;
    /// One of a run's own metadata records ([`read_run_record`]), never the image.
    fn run_record(&self, backend_id: &str, record: RunRecord) -> io::Result<RecordRead>;
    /// Free space on the runs filesystem and its loop backing, read now (design 6.3).
    fn storage(&self) -> Option<StorageFree> {
        None
    }
}

/// kiln's run directories (kiln `docs/checkpoint-lease-v1.md`, "Run metadata").
pub const KILN_RUNS: &str = "/var/lib/kiln/runs";
/// kiln's image registry root (kiln `docs/image-identity-v1.md`).
pub const KILN_IMAGE_REGISTRY: &str = "/var/lib/kiln/image-registry";

pub struct KilnWorkers {
    bin: KilnBinary,
    cgroup_root: PathBuf,
    runs: PathBuf,
    registry: PathBuf,
    /// False only for socket tests whose host has no kiln storage.
    storage_probes: bool,
    /// The executable whose processes the scan trusts, when not `bin` (tests only).
    trusted_image: Option<PathBuf>,
}

impl KilnWorkers {
    pub fn new(bin: PathBuf) -> Self {
        Self {
            bin: KilnBinary::new(bin),
            cgroup_root: PathBuf::from("/sys/fs/cgroup/kiln"),
            runs: PathBuf::from(KILN_RUNS),
            registry: PathBuf::from(KILN_IMAGE_REGISTRY),
            storage_probes: true,
            trusted_image: None,
        }
    }

    /// Another trusted executable for the process scan, for tests whose kiln is a script.
    #[cfg(test)]
    pub fn with_trusted_image(mut self, image: PathBuf) -> Self {
        self.trusted_image = Some(image);
        self
    }

    /// No storage probes (tests on a host without kiln's XFS runs): supported as far as
    /// the CLI goes, capacity unknown.
    #[cfg(test)]
    pub fn without_storage_probes(mut self) -> Self {
        self.storage_probes = false;
        self
    }

    /// Another image registry root, for tests (only the trust probe reads it).
    pub fn with_registry_root(mut self, registry: PathBuf) -> Self {
        self.registry = registry;
        self
    }
}

impl Workers for KilnWorkers {
    fn run(&self, args: KilnArgs, deadline: Instant, cancel: CancellationToken) -> WorkerFuture {
        let bin = self.bin.clone();
        Box::pin(async move {
            process::run(
                &process::Request {
                    tool: process::Tool::Kiln {
                        bin: &bin,
                        args: &args,
                    },
                    stdin: b"",
                    deadline,
                    max_output: WORKER_OUTPUT,
                },
                &cancel,
            )
            .await
        })
    }

    fn processes(&self) -> io::Result<Vec<ProcessArgs>> {
        let kiln = match &self.trusted_image {
            Some(image) => {
                let meta = std::fs::metadata(image)?;
                (meta.dev(), meta.ino())
            }
            None => kiln_identity(&self.bin)?,
        };
        process_table(kiln)
    }

    fn support(&self, deadline: Instant, cancel: CancellationToken) -> SupportFuture {
        let bin = self.bin.clone();
        let cgroup_root = self.cgroup_root.clone();
        // Design 6.3 and 7: captures need XFS project quotas where kiln's runs live, and
        // image identity needs kiln's registry root to be trustworthy.
        let storage = if self.storage_probes {
            storage_support(&self.runs, &self.registry)
        } else {
            Ok(())
        };
        Box::pin(async move {
            let core = kilnd_exec_core::runtime::kiln_direct::DirectKiln::new(&bin, &cgroup_root);
            let leases = match core.capabilities(None, deadline, &cancel).await {
                Ok(caps) if caps.features & FEATURE_CHECKPOINT_LEASE != 0 => Ok(()),
                Ok(_) => Err("the installed kiln does not grant checkpoint leases".to_string()),
                Err(e) => Err(format!("kiln capabilities: {e}")),
            };
            // Removal and inventory need only these two, never the storage probes or
            // leases (C5b-2 adversarial review MEDIUM 1): a host that lost its project
            // quota still removes what it holds.
            let removal = async {
                let out = process::run(
                    &process::Request {
                        tool: process::Tool::Kiln {
                            bin: &bin,
                            args: &KilnArgs::checkpoint_ls(),
                        },
                        stdin: b"",
                        deadline,
                        max_output: WORKER_OUTPUT,
                    },
                    &cancel,
                )
                .await
                .map_err(|e| format!("kiln checkpoint ls: {e}"))?;
                let text = success_stdout(&out).ok_or("kiln checkpoint ls failed")?;
                parse_inventory(text)?;
                // Removal must be generation-checked: an older kiln would delete any
                // generation published under the name.
                let out = process::run(
                    &process::Request {
                        tool: process::Tool::Kiln {
                            bin: &bin,
                            args: &KilnArgs::checkpoint_rm_help(),
                        },
                        stdin: b"",
                        deadline,
                        max_output: WORKER_OUTPUT,
                    },
                    &cancel,
                )
                .await
                .map_err(|e| format!("kiln checkpoint rm --help: {e}"))?;
                match success_stdout(&out) {
                    Some(help) if help.contains("--generation") => Ok(()),
                    _ => Err(
                        "the installed kiln's checkpoint rm does not check generations".to_string(),
                    ),
                }
            }
            .await;
            Support {
                removal: removal.is_ok(),
                // The storage verdict first, as before.
                new_work: storage.and(leases).and(removal),
            }
        })
    }

    fn run_record(&self, backend_id: &str, record: RunRecord) -> io::Result<RecordRead> {
        read_run_record(&self.runs, backend_id, record)
    }

    fn storage(&self) -> Option<StorageFree> {
        self.storage_probes
            .then(|| storage_free(&self.runs))
            .flatten()
    }
}

// --- Storage probes (C5b-2, design 6.3) ----------------------------------------------

/// XFS's `f_type`.
pub const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
/// The loop driver's block major.
pub const LOOP_MAJOR: u32 = 7;

/// The runs filesystem's mount, from the helper's own mountinfo: the last (topmost)
/// entry mounted exactly at `runs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunsMount {
    pub fstype: String,
    /// `prjquota` or `pquota` among the super options.
    pub project_quota: bool,
    pub device: (u32, u32),
}

/// Parses `/proc/<pid>/mountinfo` (proc(5)) for the entry at `runs`. Mount points are
/// octal-escaped (`\040` for a space); an entry with a malformed device is refused.
pub fn runs_mount(mountinfo: &str, runs: &Path) -> Result<RunsMount, String> {
    let unescape = |field: &str| -> Vec<u8> {
        let bytes = field.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let octal = bytes
                .get(i + 1..i + 4)
                .filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
            match octal {
                Some(d) => {
                    out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                    i += 4;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        out
    };
    use std::os::unix::ffi::OsStrExt;
    let mut found = None;
    for line in mountinfo.lines() {
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let head: Vec<&str> = head.split(' ').collect();
        let tail: Vec<&str> = tail.split(' ').collect();
        if head.len() < 5 || tail.len() < 3 || unescape(head[4]) != runs.as_os_str().as_bytes() {
            continue;
        }
        let device = head[2]
            .split_once(':')
            .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
            .ok_or_else(|| format!("malformed device {:?} for {}", head[2], runs.display()))?;
        found = Some(RunsMount {
            fstype: tail[0].to_string(),
            project_quota: tail[2].split(',').any(|o| o == "prjquota" || o == "pquota"),
            device,
        });
    }
    found.ok_or_else(|| format!("{} is not a mount point", runs.display()))
}

/// A loop device's `loop/backing_file` text: the path, or `None` if the file was
/// deleted or the text is not one absolute path.
pub fn backing_path(text: &str) -> Option<PathBuf> {
    let path = text.strip_suffix('\n').unwrap_or(text);
    (path.starts_with('/') && !path.ends_with(" (deleted)") && !path.contains('\n'))
        .then(|| PathBuf::from(path))
}

/// Whether kiln's registry root is one kiln itself trusts (kiln `image.rs`,
/// `trusted_registry`): absent (nothing registered yet), or a real directory owned by
/// root and not group or other writable.
pub fn registry_trusted(meta: io::Result<std::fs::Metadata>) -> Result<(), String> {
    match meta {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("kiln's image registry: {e}")),
        Ok(m) if m.file_type().is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 => Ok(()),
        Ok(_) => Err(
            "kiln's image registry is not a root-owned directory closed to group and others".into(),
        ),
    }
}

/// The capability half of the storage probes: runs is XFS with project quotas, and the
/// image registry is trusted.
fn storage_support(runs: &Path, registry: &Path) -> Result<(), String> {
    registry_trusted(std::fs::symlink_metadata(registry))?;
    let mount = runs_mount(&own_mountinfo()?, runs)?;
    if mount.fstype != "xfs" || filesystem_type(runs)? != XFS_SUPER_MAGIC {
        return Err(format!("{} is not XFS", runs.display()));
    }
    if !mount.project_quota {
        return Err(format!(
            "{} is mounted without project quotas",
            runs.display()
        ));
    }
    Ok(())
}

/// The capacity half: free bytes on runs and on its loop device's backing filesystem,
/// each `None` when it cannot be read (and the backing's also when runs is not on a
/// loop device), never a guess.
fn storage_free(runs: &Path) -> Option<StorageFree> {
    let runs_free_bytes = free_bytes(runs)?;
    let backing_free_bytes = (|| {
        let mount = runs_mount(&own_mountinfo().ok()?, runs).ok()?;
        if mount.device.0 != LOOP_MAJOR {
            return None;
        }
        let text = std::fs::read_to_string(format!(
            "/sys/dev/block/{}:{}/loop/backing_file",
            mount.device.0, mount.device.1
        ))
        .ok()?;
        free_bytes(&backing_path(&text)?)
    })();
    Some(StorageFree {
        runs_free_bytes,
        backing_free_bytes,
    })
}

#[cfg(target_os = "linux")]
fn own_mountinfo() -> Result<String, String> {
    crate::sys::procfs::read_to_string(&format!("{}/mountinfo", std::process::id()))
        .map_err(|e| format!("mountinfo: {e}"))
}

#[cfg(target_os = "linux")]
fn filesystem_type(path: &Path) -> Result<i64, String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: a NUL-terminated path and a zeroed out-parameter of the right type.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut stat) } != 0 {
        return Err(format!(
            "statfs {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_type as i64)
}

#[cfg(target_os = "linux")]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: as in `filesystem_type`.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    (stat.f_bavail as u64).checked_mul(stat.f_frsize as u64)
}

/// Production runs on Linux only: elsewhere nothing is known.
#[cfg(not(target_os = "linux"))]
fn own_mountinfo() -> Result<String, String> {
    Err("no mountinfo on this platform".into())
}

#[cfg(not(target_os = "linux"))]
fn filesystem_type(_path: &Path) -> Result<i64, String> {
    Err("no statfs on this platform".into())
}

#[cfg(not(target_os = "linux"))]
fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

// --- A run's own records (C5a) -------------------------------------------------------

/// The most one run record may hold; kiln's own bound for its records.
pub const MAX_RUN_RECORD_BYTES: usize = 4096;

/// One of a run's root-owned metadata records, read without following any link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunRecord {
    /// `<run>/image`: the run's image reference (kiln `docs/image-identity-v1.md`).
    Image,
    /// `<run>/layout`: the overlay options read back from the kernel.
    Layout,
}

impl RunRecord {
    pub fn name(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Layout => "layout",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordRead {
    Text(String),
    /// The run directory or the record does not exist: a run from an older kiln, or
    /// no run at all.
    Missing,
    /// Something root's kiln never writes: a link, another file type or owner, open
    /// permissions, oversized or non-UTF-8 content. The text is a short redacted reason.
    Hostile(String),
}

/// `openat(dir, name, flags)`, retried on EINTR, as an owned descriptor.
fn open_at(dir: &impl AsRawFd, name: &str, flags: libc::c_int) -> io::Result<OwnedFd> {
    let name = std::ffi::CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    loop {
        // SAFETY: `dir` is an open descriptor and `name` is NUL-terminated.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: openat just returned this descriptor, owned by nothing else.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}

/// Reads `<runs>/<backend_id>/<record>` without following a link in either of the
/// last two components and without opening anything but a regular file for reading.
/// Both must belong to the helper's effective user, the directory writable by it
/// alone and the record readable by it alone (kiln writes 0600 in 0700), and the
/// record must be UTF-8 of at most [`MAX_RUN_RECORD_BYTES`]. An `Err` is any other
/// I/O failure, including on `runs` itself.
pub fn read_run_record(runs: &Path, backend_id: &str, record: RunRecord) -> io::Result<RecordRead> {
    let hostile = |why: &str| Ok(RecordRead::Hostile(why.to_string()));
    if !crate::runtime::kiln_direct::valid_kiln_id(backend_id) {
        return hostile("invalid backend ID");
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let runs = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(runs)?;
    let run = match open_at(
        &runs,
        backend_id,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(fd) => std::fs::File::from(fd),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(RecordRead::Missing),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
            return hostile("the run directory is not a directory");
        }
        Err(e) => return Err(e),
    };
    let meta = run.metadata()?;
    if meta.uid() != euid || meta.mode() & 0o022 != 0 {
        return hostile("the run directory has another owner or is writable by others");
    }
    let file = match open_at(
        &run,
        record.name(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
    ) {
        Ok(fd) => std::fs::File::from(fd),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(RecordRead::Missing),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return hostile(match record {
                RunRecord::Image => "the image record is a symbolic link",
                RunRecord::Layout => "the layout record is a symbolic link",
            });
        }
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    let kind = meta.file_type();
    if !kind.is_file() {
        return hostile(if kind.is_fifo() || kind.is_socket() {
            "a run record is a FIFO or socket"
        } else {
            "a run record is not a regular file"
        });
    }
    if meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return hostile("a run record has another owner or is open to others");
    }
    if meta.size() > MAX_RUN_RECORD_BYTES as u64 {
        return hostile("a run record is too large");
    }
    let mut data = Vec::with_capacity(MAX_RUN_RECORD_BYTES + 1);
    file.take(MAX_RUN_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_RUN_RECORD_BYTES {
        return hostile("a run record is too large");
    }
    match String::from_utf8(data) {
        Ok(text) => Ok(RecordRead::Text(text)),
        Err(_) => hostile("a run record is not UTF-8"),
    }
}

/// The value of `<key> <value>`, non-empty.
fn record_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .strip_prefix(' ')
        .filter(|v| !v.is_empty())
}

/// A canonical unsigned decimal: digits only, no leading zero but `0` itself.
fn canonical_decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

/// kiln's directory identity, `<16 lowercase hex fsid>:<ino>:<btime sec>.<9 digits>`,
/// exactly as its `DirIdentity::text` prints it.
fn canonical_directory(text: &str) -> bool {
    let parts: Vec<&str> = text.split(':').collect();
    let [fsid, ino, btime] = parts.as_slice() else {
        return false;
    };
    let Some((sec, nsec)) = btime.split_once('.') else {
        return false;
    };
    let digits = sec.strip_prefix('-').unwrap_or(sec);
    fsid.len() == 16
        && fsid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && canonical_decimal(ino).is_some()
        && canonical_decimal(digits).is_some()
        && sec.parse::<i64>().is_ok()
        && sec != "-0"
        && nsec.len() == 9
        && nsec.bytes().all(|b| b.is_ascii_digit())
}

/// A run's `image` record (kiln `Reference::text`), exactly as kiln writes it:
/// `Ok(Ok((name, sha256)))` for a recorded identity, `Ok(Err(reason))` for
/// `identity none <reason>`, and `Err` for anything else.
pub fn parse_image_ref(text: &str) -> Result<Result<(String, Digest), String>, String> {
    let malformed = |why: &str| Err(format!("malformed image reference: {why}"));
    let Some(body) = text.strip_suffix('\n') else {
        return malformed("no final newline");
    };
    if body.contains(['\r', '\0']) {
        return malformed("a control character");
    }
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.first() != Some(&"kiln-image-ref 1") {
        return malformed("unexpected header");
    }
    let Some(name) = lines.get(1).and_then(|l| record_value(l, "name")) else {
        return malformed("no name");
    };
    if crate::validation::validate_image_name(name).is_err() {
        return malformed("invalid image name");
    }
    match lines[2..] {
        [identity] => match identity.strip_prefix("identity none ") {
            Some(reason) if !reason.is_empty() => Ok(Err(reason.to_string())),
            _ => malformed("unexpected identity line"),
        },
        [generation, sha256, directory] => {
            let generation = record_value(generation, "generation").and_then(canonical_decimal);
            if generation.is_none_or(|g| g == 0) {
                return malformed("generation");
            }
            let Some(Ok(sha256)) = record_value(sha256, "sha256").map(Digest::parse) else {
                return malformed("sha256");
            };
            if !record_value(directory, "directory").is_some_and(canonical_directory) {
                return malformed("directory");
            }
            Ok(Ok((name.to_string(), sha256)))
        }
        _ => malformed("unexpected lines"),
    }
}

/// The overlay features a verified layout must report first (kiln `parse_layout`).
pub const PINNED_EFFECTIVE: &str = "index=off metacopy=off nfs_export=off redirect_dir=nofollow";
const PINNED_OPTIONS: &str = "index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off";

/// A run's `layout` record (kiln `layout_text`), in kiln's exact line order:
/// `Ok(Ok(()))` for `verified yes` with the pinned effective features, `Ok(Err(reason))`
/// for `verified no <reason>`, and `Err` for anything else.
pub fn parse_layout(text: &str) -> Result<Result<(), String>, String> {
    let malformed = |why: &str| Err(format!("malformed layout record: {why}"));
    let Some(body) = text.strip_suffix('\n') else {
        return malformed("no final newline");
    };
    if body.contains(['\r', '\0']) {
        return malformed("a control character");
    }
    let mut lines = body.split('\n').peekable();
    if lines.next() != Some("kiln-layout 1") {
        return malformed("unexpected header");
    }
    if lines.next().and_then(|l| l.strip_prefix("pinned ")) != Some(PINNED_OPTIONS) {
        return malformed("unexpected pinned options");
    }
    // kiln omits `defaults`, `super` and `effective` when it read nothing back.
    let mut effective = None;
    if !lines.peek().is_some_and(|l| l.starts_with("verified ")) {
        for key in ["defaults", "super", "effective"] {
            match lines.next().and_then(|l| record_value(l, key)) {
                Some(value) => effective = Some(value),
                None => return malformed("missing or unexpected option line"),
            }
        }
    }
    let verified = match lines.next().and_then(|l| l.strip_prefix("verified ")) {
        Some("yes") => match effective {
            Some(e)
                if e == PINNED_EFFECTIVE
                    || e.strip_prefix(PINNED_EFFECTIVE)
                        .is_some_and(|r| r.starts_with(' ')) =>
            {
                Ok(())
            }
            _ => return malformed("verified without the pinned effective features"),
        },
        Some(v) => match v.strip_prefix("no ") {
            Some(reason) => Err(reason.to_string()),
            None => return malformed("unexpected verification"),
        },
        None => return malformed("no verification line"),
    };
    for line in lines {
        if !record_value(line, "generated").is_some_and(|p| p.starts_with('/')) {
            return malformed("unexpected trailing line");
        }
    }
    Ok(verified)
}

/// The exit code of a run whose stdout and stderr both reached EOF untruncated.
pub fn exit_code(out: &Outcome) -> Option<i32> {
    let complete = |data: &crate::model::Captured, completion: &CaptureCompletion| {
        *completion == CaptureCompletion::Eof && !data.truncated() && data.total_bytes_known
    };
    match &out.finish {
        Finish::Exited(status)
            if complete(&out.stdout, &out.stdout_completion)
                && complete(&out.stderr, &out.stderr_completion) =>
        {
            status.code()
        }
        _ => None,
    }
}

/// Stdout of a complete, successful run.
pub fn success_stdout(out: &Outcome) -> Option<&str> {
    (exit_code(out) == Some(0))
        .then(|| std::str::from_utf8(&out.stdout.data).ok())
        .flatten()
}

/// kiln's failure exit for checkpoint commands.
pub const CHECKPOINT_FAILED: i32 = 125;
/// `kiln create`'s exit for refusals known before allocation.
pub const CREATE_PREFLIGHT_FAILED: i32 = 124;

/// `kiln-checkpoint-removed 1`: whether anything existed.
pub fn parse_removed(text: &str) -> Result<bool, String> {
    match text {
        "kiln-checkpoint-removed 1\nexisted yes\n" => Ok(true),
        "kiln-checkpoint-removed 1\nexisted no\n" => Ok(false),
        _ => Err("malformed removal record".into()),
    }
}

/// One `kiln-checkpoint-inventory 1` line: its kind, owner instance (`None` for `-`)
/// and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryLine {
    pub kind: Option<ItemKind>,
    pub instance: Option<Id128>,
    pub name: String,
}

impl InventoryLine {
    /// The capture generation a staging or removal entry's name records:
    /// `.staging-C-G-nonce` and `.removing-C-G-pid-n`. None for a published artifact
    /// (its header holds it), an older kiln's `.removing-C-pid-n`, or `G` 0 (unknown).
    pub fn generation(&self) -> Option<u64> {
        let rest = match self.kind? {
            ItemKind::Published => return None,
            ItemKind::Staging => self.name.strip_prefix(".staging-")?.get(36..)?,
            ItemKind::Removing => self.name.strip_prefix(".removing-")?.get(36..)?,
        };
        let parts: Vec<&str> = rest.split('-').collect();
        let generation = match (self.kind?, parts.as_slice()) {
            (ItemKind::Staging, [g, _]) | (ItemKind::Removing, [g, _, _]) => *g,
            _ => return None,
        };
        if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        generation.parse().ok().filter(|g| *g != 0)
    }

    /// The checkpoint a published, staging or removal entry belongs to.
    pub fn checkpoint(&self) -> Option<CheckpointId> {
        let id = match self.kind? {
            ItemKind::Published => self.name.as_str(),
            ItemKind::Staging => self.name.strip_prefix(".staging-")?.get(..35)?,
            ItemKind::Removing => self.name.strip_prefix(".removing-")?.get(..35)?,
        };
        CheckpointId::parse(id).ok()
    }
}

/// Strict: the header, then `published|staging|removing|unknown <instance or -> <name>`
/// per line, and a final newline. kiln lists names lossily; a name holding a newline
/// makes the listing malformed, so it is never read as complete.
pub fn parse_inventory(text: &str) -> Result<Vec<InventoryLine>, String> {
    let body = text
        .strip_suffix('\n')
        .ok_or("inventory without a final newline")?;
    let mut lines = body.split('\n');
    if lines.next() != Some("kiln-checkpoint-inventory 1") {
        return Err("unexpected inventory header".into());
    }
    let mut out = Vec::new();
    for line in lines {
        let (word, rest) = line.split_once(' ').ok_or("malformed inventory line")?;
        let (instance, name) = rest.split_once(' ').ok_or("malformed inventory line")?;
        let kind = match word {
            "published" => Some(ItemKind::Published),
            "staging" => Some(ItemKind::Staging),
            "removing" => Some(ItemKind::Removing),
            "unknown" => None,
            _ => return Err("unknown inventory kind".into()),
        };
        let instance = match instance {
            "-" if kind.is_none() => None,
            text => Some(Id128::parse(text)?),
        };
        if name.is_empty() {
            return Err("empty inventory name".into());
        }
        let line = InventoryLine {
            kind,
            instance,
            name: name.to_string(),
        };
        if kind.is_some() && line.checkpoint().is_none() {
            return Err("inventory entry without a checkpoint ID".into());
        }
        out.push(line);
    }
    Ok(out)
}

/// How kiln's parser (clap 4) takes one long option of a subcommand.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opt {
    /// A value, at most once.
    Text,
    /// A value, any number of times (kiln's `Vec<String>` options).
    Repeated,
    /// A nonempty value, any number of times (kiln's `Vec<PathBuf>`: clap refuses an
    /// empty path).
    Paths,
    /// A `u64` value (clap's unsigned parser: Rust's, so `+9` too), at most once.
    U64,
    /// A `u16` value through clap's signed parser (an `i64` in range, so `+1` and `-0`
    /// too), at most once.
    U16,
    /// No value, at most once.
    Flag,
}

/// The long options after a kiln subcommand, exactly as kiln's parser takes them: an
/// option as `--name=V` or `--name V` (where V does not look like an option), a flag
/// alone, numbers that parse, nothing repeated but a `Repeated`/`Paths` option, and exactly
/// `positionals` other words, every word after the first `--` (or a lone `-`) being
/// one. `None` where kiln itself would refuse the command line (an unknown or short
/// option, a missing or malformed value, a repeat, a missing or extra word).
fn options<'a>(
    args: &'a [String],
    spec: &[(&str, Opt)],
    positionals: usize,
) -> Option<Vec<(&'a str, &'a str)>> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut words = 0;
    let mut escaped = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if escaped || arg == "-" || !arg.starts_with('-') {
            words += 1;
            continue;
        }
        if arg == "--" {
            escaped = true;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (arg.as_str(), None),
        };
        let (_, kind) = spec.iter().find(|(n, _)| *n == name)?;
        let value = match (kind, inline) {
            (Opt::Flag, None) => "",
            (Opt::Flag, Some(_)) => return None,
            (_, Some(value)) => value,
            (_, None) => args.next().filter(|v| *v == "-" || !v.starts_with('-'))?,
        };
        let parses = match kind {
            Opt::U64 => value.parse::<u64>().is_ok(),
            Opt::U16 => value
                .parse::<i64>()
                .is_ok_and(|v| (0..=i64::from(u16::MAX)).contains(&v)),
            Opt::Paths => !value.is_empty(),
            _ => true,
        };
        let repeatable = matches!(kind, Opt::Repeated | Opt::Paths);
        if !parses || (!repeatable && out.iter().any(|(n, _)| *n == name)) {
            return None;
        }
        out.push((name, value));
    }
    (words == positionals).then_some(out)
}

/// The value of `name`, given at most once by [`options`].
fn value<'a>(options: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    options.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// The artifact a kiln command line reads, parsed exactly as kiln's top-level grammar
/// (kiln `runtime/src/main.rs`, no global options): `checkpoint capture|inspect|rm`
/// with its required options and capture's source sandbox, or `create` with
/// `--from-checkpoint=I/C` (the bool). Anything else, `exec` and `run` included,
/// reads no artifact, and no word after `--` is ever an option.
fn artifact_reader(argv: &[String]) -> Option<(&str, &str, bool)> {
    use Opt::{Flag, Paths, Repeated, Text, U16, U64};
    let (command, rest) = argv.get(1..)?.split_first()?;
    match command.as_str() {
        "checkpoint" => {
            let (sub, rest) = rest.split_first()?;
            let identity = [("--instance", Text), ("--checkpoint", Text)];
            let (extra, required, positionals): (&[(&str, Opt)], &[&str], usize) =
                match sub.as_str() {
                    "capture" => (
                        &[("--generation", U64), ("--max-bytes", U64)],
                        &["--generation", "--max-bytes"],
                        1,
                    ),
                    "inspect" => (&[("--verify", Flag)], &[], 0),
                    "rm" => (&[("--generation", U64)], &[], 0),
                    _ => return None,
                };
            let spec: Vec<(&str, Opt)> = identity.iter().chain(extra).copied().collect();
            let options = options(rest, &spec, positionals)?;
            if !required.iter().all(|r| value(&options, r).is_some()) {
                return None;
            }
            Some((
                value(&options, "--instance")?,
                value(&options, "--checkpoint")?,
                false,
            ))
        }
        "create" => {
            let options = options(
                rest,
                &[
                    ("--require-exec-protocol", U16),
                    ("--hostname", Text),
                    ("--image", Text),
                    ("--memory", Text),
                    ("--cpus", Text),
                    ("--pids", Text),
                    ("--disk", Text),
                    ("--read-only", Flag),
                    ("--writable", Paths),
                    ("--net", Text),
                    ("--allow", Repeated),
                    ("--from-checkpoint", Text),
                ],
                0,
            )?;
            // kiln: `--writable` requires `--read-only`.
            if value(&options, "--writable").is_some() && value(&options, "--read-only").is_none() {
                return None;
            }
            let (instance, checkpoint) = value(&options, "--from-checkpoint")?.split_once('/')?;
            Some((instance, checkpoint, true))
        }
        _ => None,
    }
}

/// A `create --from-checkpoint` command line's source, `I/C`.
fn source_text(argv: &[String]) -> Option<String> {
    match artifact_reader(argv)? {
        (instance, checkpoint, true) => Some(format!("{instance}/{checkpoint}")),
        _ => None,
    }
}

/// The artifact a process reads, if any (see [`artifact_reader`]): a `checkpoint`
/// worker, or a `--from-checkpoint` create that is not a restored sandbox's shim. The
/// table holds only processes of the trusted kiln executable, so a root operator's own
/// kiln command blocks absence too, while an Exec's caller-controlled arguments (after
/// `kiln exec`'s `--`, or another binary's) never do.
pub fn named_artifact(process: &ProcessArgs) -> Option<(String, String)> {
    let (instance, checkpoint, restore) = artifact_reader(&process.argv)?;
    // A restoring shim holds the artifact's lock, which keeps kiln's removal busy;
    // once restored neither it nor its forks read it again. Only the CLI is a worker.
    if restore && process.in_shim_session {
        return None;
    }
    Some((instance.into(), checkpoint.into()))
}

/// The trusted kiln executable's identity (device, inode), which a process's `exe` must
/// be for its arguments to be evidence.
pub fn kiln_identity(bin: &KilnBinary) -> io::Result<(u64, u64)> {
    let meta = std::fs::metadata(bin.verified()?)?;
    Ok((meta.dev(), meta.ino()))
}

/// The most process directories one scan reads; a busier host fails the scan, and so
/// certifies no absence.
#[cfg(target_os = "linux")]
const MAX_PROCESSES: usize = 65_536;

/// Every live artifact-reading kiln process's arguments and session leadership, read
/// beneath the helper's private procfs instance (`crate::sys::procfs`: no link followed
/// but `exe`, no mount crossed). See [`scan`].
#[cfg(target_os = "linux")]
pub(crate) fn process_table(kiln: (u64, u64)) -> io::Result<Vec<ProcessArgs>> {
    use crate::sys::procfs;
    let pids = procfs::read_root_dir(MAX_PROCESSES)?
        .into_iter()
        .filter_map(|entry| std::str::from_utf8(&entry.name).ok()?.parse::<u32>().ok());
    scan(
        pids,
        kiln,
        |pid| procfs::read(&format!("{pid}/stat")),
        |pid| {
            let mut cmdline = Vec::new();
            procfs::open(&format!("{pid}/cmdline"), libc::O_RDONLY)?
                .take(256 << 10)
                .read_to_end(&mut cmdline)?;
            Ok(cmdline)
        },
        |pid| {
            let meta =
                procfs::open_image(i32::try_from(pid).map_err(io::Error::other)?)?.metadata()?;
            Ok((meta.dev(), meta.ino()))
        },
    )
}

/// The scan over `pids`, with the three procfs reads. A process counts only when its
/// arguments read an artifact ([`artifact_reader`]), its running image (`exe`) is the
/// trusted kiln executable (`kiln`: device and inode) and its start time (`stat` field
/// 22) is the same before its arguments were read and after its image was: argv text,
/// another binary or a reused PID is no evidence. A process that exits during the scan,
/// or whose image the helper may not inspect (a non-dumpable sandbox init, or one with
/// capabilities beyond the helper's), is skipped; any other failure fails the scan.
pub fn scan(
    pids: impl IntoIterator<Item = u32>,
    kiln: (u64, u64),
    stat: impl Fn(u32) -> io::Result<Vec<u8>>,
    cmdline: impl Fn(u32) -> io::Result<Vec<u8>>,
    image: impl Fn(u32) -> io::Result<(u64, u64)>,
) -> io::Result<Vec<ProcessArgs>> {
    let gone = |e: &io::Error| {
        e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
    };
    // `comm` is the process's own bytes, read as bytes ([`crate::proc_stat`]): one
    // that isn't UTF-8 anywhere on the node must not fail the scan. The session (field
    // 6) and the start time (field 22).
    let identity = |pid: u32| -> io::Result<(u32, u64)> {
        let stat = stat(pid)?;
        let fields = crate::proc_stat::fields(&stat)
            .map_err(|_| io::Error::other("malformed process stat"))?;
        match (
            fields.get(3).map(|s| s.parse::<u32>()),
            fields.get(19).map(|s| s.parse::<u64>()),
        ) {
            (Some(Ok(session)), Some(Ok(start))) => Ok((session, start)),
            _ => Err(io::Error::other("malformed process stat")),
        }
    };
    let mut out = Vec::new();
    for pid in pids {
        let (session, start) = match identity(pid) {
            Ok(identity) => identity,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        let cmdline = match cmdline(pid) {
            Ok(cmdline) => cmdline,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        // NUL-terminated words; an empty word is a word, as kiln's parser sees it.
        let words: Vec<&[u8]> = if cmdline.is_empty() {
            Vec::new()
        } else {
            cmdline
                .strip_suffix(&[0])
                .unwrap_or(&cmdline)
                .split(|b| *b == 0)
                .collect()
        };
        let argv: Vec<String> = words
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        // Kernel threads and zombies have no arguments; most processes read nothing.
        // kiln refuses a non-UTF-8 word anywhere but a `--writable` path.
        if artifact_reader(&argv).is_none() || !utf8_where_kiln_needs_it(&words) {
            continue;
        }
        match image(pid) {
            Ok(image) if image == kiln => {}
            Ok(_) => continue,
            Err(e) if gone(&e) || matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
                continue;
            }
            Err(e) => return Err(e),
        }
        match identity(pid) {
            Ok((_, again)) if again == start => out.push((pid, session, argv)),
            Ok(_) => {}
            Err(e) if gone(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(shim_sessions(out))
}

/// Production runs on Linux only: elsewhere no scan can prove anything.
#[cfg(not(target_os = "linux"))]
pub(crate) fn process_table(_kiln: (u64, u64)) -> io::Result<Vec<ProcessArgs>> {
    Err(io::Error::other("no process table on this platform"))
}

/// Whether every word kiln parses as a `String` is UTF-8 (clap refuses one that is
/// not), so only a `--writable` path (`PathBuf`: `--writable=P` or the word after
/// `--writable`, before any `--`) may hold other bytes; so may the program name, which
/// clap never parses. Called only for a command line [`artifact_reader`] accepts, whose
/// `--writable` values are option values.
fn utf8_where_kiln_needs_it(words: &[&[u8]]) -> bool {
    let mut escaped = false;
    let mut path_next = false;
    words.iter().skip(1).all(|word| {
        let path = !escaped && (path_next || word.starts_with(b"--writable="));
        path_next = !escaped && *word == b"--writable";
        escaped |= *word == b"--";
        path || std::str::from_utf8(word).is_ok()
    })
}

/// The reason token at the start of a `kiln create` cause line (exit 124), or none.
pub fn create_reason(stderr: &[u8]) -> Option<crate::checkpoint::Reason> {
    let text = String::from_utf8_lossy(stderr);
    text.lines().find_map(|line| {
        let line = line.trim_start();
        // anyhow's numbered causes: `0: token: ...`.
        let line = match line.split_once(": ") {
            Some((n, rest)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => rest,
            _ => line,
        };
        let line = line.strip_prefix("Error: ").unwrap_or(line);
        // A failure after allocation: `sandbox shim failed during setup: <token>: …`.
        let line = line
            .strip_prefix("sandbox shim failed during setup: ")
            .unwrap_or(line);
        let (token, _) = line.split_once(':')?;
        // `sandbox_unsupported:workspace_checkpoint` holds a colon of its own.
        let token = if token == "sandbox_unsupported" {
            "sandbox_unsupported:workspace_checkpoint"
        } else {
            token
        };
        crate::checkpoint::Reason::from_token(token)
    })
}
