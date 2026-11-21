//! The root side of `kilnd release-ambiguous` (docs/setup.md, "Releasing an ambiguous
//! reservation"): what it needs as root before it gives root up, and how it reports.
//! The proof and the release are [`crate::manager::Manager::release_ambiguous`].

use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};

use crate::manager::{ReleaseProved, ReleaseRefusal, RunsDirectory};

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
/// kilnd, or anything else, holds this instance's state lock (EX_TEMPFAIL).
pub const EXIT_DAEMON_RUNNING: u8 = 75;
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

impl RunsDirectory for RunsRoot {
    fn entries(&self) -> Result<Vec<OsString>> {
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
