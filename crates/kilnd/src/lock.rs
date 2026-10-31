//! Small advisory file locks used to coordinate daemon ownership.

use std::ffi::{CString, OsStr};
use std::fs::File;
#[cfg(test)]
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(test)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A nonblocking exclusive lock held for as long as its file stays open.
///
/// The pathname is deliberately persistent. Removing a lock file while it is
/// held would let another process lock a different inode at the same path.
pub(crate) struct ExclusiveFileLock {
    _file: File,
    #[allow(dead_code)]
    path: PathBuf,
    #[cfg(test)]
    drop_probe: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl ExclusiveFileLock {
    #[cfg(test)]
    pub(crate) fn acquire(path: &Path, resource: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open {resource} lock {}", path.display()))?;
        Self::finish_acquire(file, path, resource, || {
            let meta = std::fs::symlink_metadata(path)
                .with_context(|| format!("recheck {resource} lock {}", path.display()))?;
            Ok((meta.is_file(), meta.dev(), meta.ino()))
        })
    }

    pub(crate) fn acquire_at(
        directory: &File,
        name: &OsStr,
        path: &Path,
        resource: &str,
    ) -> Result<Self> {
        let name = CString::new(name.as_bytes()).context("lock filename contains NUL")?;
        let base_flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // Open an existing stable inode first. If it is absent, O_EXCL makes
        // concurrent creation explicit; the loser then opens the winner's
        // inode instead of relying on platform-specific O_CREAT races.
        // SAFETY: directory is live, name is NUL-terminated, and the flags
        // are valid for openat.
        let mut fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                base_flags,
            )
        };
        if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            // SAFETY: same valid directory/name; mode is consumed by O_CREAT.
            fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    base_flags | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )
            };
            if fd < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists
            {
                // SAFETY: a contender created the entry; inspect that exact
                // no-follow target through the still-pinned directory.
                fd = unsafe {
                    libc::openat(directory.as_raw_fd(), name.as_ptr(), base_flags)
                };
            }
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open {resource} lock {}", path.display()));
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        Self::finish_acquire(file, path, resource, || {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: directory and name are live, stat points to writable
            // storage, and AT_SYMLINK_NOFOLLOW prevents a pathname recheck
            // from traversing a replacement symlink.
            if unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("recheck {resource} lock {}", path.display()));
            }
            // SAFETY: fstatat initialized stat on success.
            let stat = unsafe { stat.assume_init() };
            // libc::dev_t differs across supported Unix targets; normalize it
            // to the u64 returned by std::os::unix::fs::MetadataExt::dev.
            #[allow(clippy::unnecessary_cast)]
            let device = stat.st_dev as u64;
            Ok((
                stat.st_mode & libc::S_IFMT == libc::S_IFREG,
                device,
                stat.st_ino,
            ))
        })
    }

    fn finish_acquire(
        mut file: File,
        path: &Path,
        resource: &str,
        recheck: impl FnOnce() -> Result<(bool, u64, u64)>,
    ) -> Result<Self> {
        let meta = file
            .metadata()
            .with_context(|| format!("inspect {resource} lock {}", path.display()))?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if !meta.is_file()
            || meta.uid() != euid
            || meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            bail!(
                "{} is not a private regular lock file owned by uid {euid}",
                path.display()
            );
        }

        // SAFETY: the descriptor is live and flock accepts any open file
        // descriptor. LOCK_NB makes contention fail instead of blocking.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!("{resource} already owned; lock is {}", path.display());
            }
            return Err(error).with_context(|| format!("lock {resource} at {}", path.display()));
        }

        // Refuse a pathname swap around open/lock. The lock protects this
        // inode; ownership is useful only while the stable pathname names it.
        let (is_file, dev, ino) = recheck()?;
        if !is_file || dev != meta.dev() || ino != meta.ino() {
            bail!("{resource} lock changed while acquiring {}", path.display());
        }

        // PID text is diagnostic only. Kernel lock ownership is authoritative.
        file.set_len(0)
            .with_context(|| format!("truncate {resource} lock {}", path.display()))?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())
            .with_context(|| format!("write {resource} lock {}", path.display()))?;

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
            #[cfg(test)]
            drop_probe: None,
        })
    }

    /// For a forked worker's keep-list: flock belongs to the open file description,
    /// so an inheriting process holds the lock until it too has closed this.
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self._file.as_raw_fd()
    }

    #[cfg(test)]
    pub(crate) fn with_drop_probe(mut self, probe: impl FnOnce() + Send + Sync + 'static) -> Self {
        self.drop_probe = Some(Box::new(probe));
        self
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(probe) = self.drop_probe.take() {
            probe();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_descriptor_is_closed_across_exec() {
        // A fork in another parallel test temporarily inherits every open FD
        // until its exec. Check CLOEXEC in a fresh process where only this
        // test can fork after acquiring the ownership lock.
        const CHILD: &str = "KILND_LOCK_CLOEXEC_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = {
                let _guard = crate::process::spawn_guard();
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "lock::tests::lock_descriptor_is_closed_across_exec",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .spawn()
                    .unwrap()
            };
            let status = child.wait().unwrap();
            assert!(status.success());
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("owner.lock");
        let owner = ExclusiveFileLock::acquire(&path, "test resource").unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();

        drop(owner);
        let next = ExclusiveFileLock::acquire(&path, "test resource")
            .expect("exec child inherited the ownership descriptor");
        drop(next);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
